#include <scx/common.bpf.h>

#include "scx_erf_sched.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)

struct erf_task_name {
	u32 task_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SHEDULER_MAX_TASKS);
	__type(key, __u32);
	__type(value, struct erf_task_plan);
} task_plans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct erf_schedule_control);
} schedule_control SEC(".maps");

static inline bool is_dec(char c)
{
	return c >= '0' && c <= '9';
}

static inline bool is_isolated_cpu(s32 cpu)
{
	return cpu >= ISOLATED_START && cpu <= ISOLATED_END;
}

static inline bool parse_sched_task_name(const char *name,
					 struct erf_task_name *task_name)
{
	u32 task_id = 0;
	bool seen_id = false;
	int i;

	if (name[0] != 't' || name[1] != 'a' || name[2] != 's' ||
	    name[3] != 'k')
		return false;

	#pragma unroll
	for (i = 4; i < SHEDULER_TASK_COMM_LEN; i++) {
		char c = name[i];

		if (c == '\0') {
			if (!seen_id)
				return false;
			task_name->task_id = task_id;
			return true;
		}

		if (!is_dec(c))
			return false;
		seen_id = true;
		task_id = task_id * 10 + (c - '0');
	}

	return false;
}

static inline bool lookup_task_plan(const struct task_struct *p,
				    struct erf_task_plan *plan)
{
	struct erf_task_name task_name;
	struct erf_task_plan *map_plan;

	if (!parse_sched_task_name(p->comm, &task_name))
		return false;

	map_plan = bpf_map_lookup_elem(&task_plans, &task_name.task_id);
	if (!map_plan)
		return false;

	*plan = *map_plan;
	return true;
}

static inline bool planned_cpu_allowed(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *online;
	bool allowed;

	online = scx_bpf_get_online_cpumask();
	allowed = bpf_cpumask_test_cpu(cpu, online) &&
		  bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
	scx_bpf_put_cpumask(online);
	return allowed;
}

static inline bool is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
}

static inline s32 pick_non_isolated_cpu(const struct task_struct *p, bool *is_idle)
{
	struct bpf_cpumask *mask;
	s32 cpu = -1;
	int i;

	*is_idle = false;

	mask = bpf_cpumask_create();
	if (!mask)
		return -1;

	bpf_cpumask_copy(mask, p->cpus_ptr);

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++)
		bpf_cpumask_clear_cpu(ISOLATED_START + i, mask);

	if (bpf_cpumask_empty((const struct cpumask *)mask))
		goto out;

	cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out;
	}

	cpu = scx_bpf_pick_any_cpu((const struct cpumask *)mask, 0);

out:
	bpf_cpumask_release(mask);
	return cpu;
}

static inline void set_cpuperf_target(s32 cpu, u32 perf_target)
{
	if (perf_target > SCX_CPUPERF_ONE)
		perf_target = SCX_CPUPERF_ONE;

	scx_bpf_cpuperf_set(cpu, perf_target);
}

s32 BPF_STRUCT_OPS(erf_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct erf_task_plan plan;
	bool is_idle = false;
	s32 cpu;

	if (lookup_task_plan(p, &plan) && planned_cpu_allowed(p, plan.cpu))
		return plan.cpu;

	cpu = pick_non_isolated_cpu(p, &is_idle);
	if (cpu >= 0) {
		if (is_idle)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return cpu;
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !is_isolated_cpu(cpu))
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

	return cpu;
}

void BPF_STRUCT_OPS(erf_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct erf_task_plan plan;
	s32 cpu;

	if (lookup_task_plan(p, &plan) && planned_cpu_allowed(p, plan.cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | plan.cpu, SCX_SLICE_DFL,
				   enq_flags);
		return;
	}

	if (is_pinned(p)) {
		cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   SCX_SLICE_DFL, enq_flags);
			return;
		}
	}

	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(erf_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!is_isolated_cpu(cpu))
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(erf_running, struct task_struct *p)
{
	struct erf_task_plan plan;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;

	if (lookup_task_plan(p, &plan) && cpu == (s32)plan.cpu) {
		set_cpuperf_target(cpu, plan.perf_target);
		return;
	}

	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(erf_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu) || runnable)
		return;

	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(erf_update_idle, s32 cpu, bool idle)
{
	if (!idle || !is_isolated_cpu(cpu))
		return;

	set_cpuperf_target(cpu, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(erf_init)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	int i;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		u32 cpu = ISOLATED_START + i;

		if (bpf_cpumask_test_cpu(cpu, online))
			scx_bpf_cpuperf_set(cpu, 0);
	}

	scx_bpf_put_cpumask(online);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(erf_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(erf_ops,
	       .select_cpu		= (void *)erf_select_cpu,
	       .enqueue			= (void *)erf_enqueue,
	       .dispatch		= (void *)erf_dispatch,
	       .running			= (void *)erf_running,
	       .stopping		= (void *)erf_stopping,
	       .update_idle		= (void *)erf_update_idle,
	       .init			= (void *)erf_init,
	       .exit			= (void *)erf_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "erf");
