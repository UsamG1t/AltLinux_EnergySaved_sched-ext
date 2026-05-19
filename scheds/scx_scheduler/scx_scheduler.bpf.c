#include <scx/common.bpf.h>

#include "scx_scheduler_sched.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define WAIT_DSQ_BASE 0x1000
#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)

struct scheduler_task_name {
	u32 task_id;
};

struct schedule_runtime_state {
	u64 base_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SCHEDULER_MAX_TASKS);
	__type(key, __u32);
	__type(value, struct schedule_task_plan);
} task_plans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct schedule_control);
} schedule_control SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct schedule_runtime_state);
} schedule_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_ISOLATED_CPUS);
	__type(key, __u32);
	__type(value, struct scheduler_debug_cpu_state);
} debug_cpu_state SEC(".maps");

static inline bool is_dec(char c)
{
	return c >= '0' && c <= '9';
}

static inline bool is_isolated_cpu(s32 cpu)
{
	return cpu >= ISOLATED_START && cpu <= ISOLATED_END;
}

static inline s32 isolated_cpu_slot(s32 cpu)
{
	if (!is_isolated_cpu(cpu))
		return -1;
	return cpu - ISOLATED_START;
}

static inline struct scheduler_debug_cpu_state *lookup_debug_cpu_state(s32 cpu)
{
	s32 slot = isolated_cpu_slot(cpu);
	u32 key;

	if (slot < 0)
		return NULL;

	key = (u32)slot;
	return bpf_map_lookup_elem(&debug_cpu_state, &key);
}

static inline void copy_task_comm(char dst[SCHEDULER_TASK_COMM_LEN],
				  const char src[SCHEDULER_TASK_COMM_LEN])
{
	__builtin_memcpy(dst, src, SCHEDULER_TASK_COMM_LEN);
}

static inline void clear_task_comm(char dst[SCHEDULER_TASK_COMM_LEN])
{
	__builtin_memset(dst, 0, SCHEDULER_TASK_COMM_LEN);
}

static inline void record_last_actor(struct scheduler_debug_cpu_state *state,
				     enum scheduler_debug_event event,
				     const struct task_struct *p)
{
	state->last_event = event;
	state->last_actor_pid = p->pid;
	state->last_actor_tgid = p->tgid;
	copy_task_comm(state->last_actor_comm, p->comm);
}

static inline void record_idle_actor(struct scheduler_debug_cpu_state *state)
{
	state->last_event = SCHEDULER_DEBUG_IDLE_ZERO;
	state->last_actor_pid = 0;
	state->last_actor_tgid = 0;
	clear_task_comm(state->last_actor_comm);
}

static inline bool parse_sched_task_name(const char *name,
					 struct scheduler_task_name *task_name)
{
	u32 task_id = 0;
	bool seen_id = false;
	int i;

	if (name[0] != 't' || name[1] != 'a' || name[2] != 's' ||
	    name[3] != 'k')
		return false;

	#pragma unroll
	for (i = 4; i < SCHEDULER_TASK_COMM_LEN; i++) {
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
				    struct schedule_task_plan *plan)
{
	struct scheduler_task_name task_name;
	struct schedule_task_plan *map_plan;

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

static inline u64 wait_dsq_id_for_cpu(s32 cpu)
{
	return WAIT_DSQ_BASE + (u64)(cpu - ISOLATED_START);
}

static inline u64 task_ready_ns(const struct schedule_task_plan *plan)
{
	return (u64)plan->ready_ms * 1000000ULL;
}

static inline u64 get_or_init_schedule_base_ns(const struct schedule_task_plan *plan,
					       u64 now)
{
	struct schedule_runtime_state *state;
	u64 candidate;
	u64 prev;
	u32 key = 0;

	state = bpf_map_lookup_elem(&schedule_runtime, &key);
	if (!state)
		return 0;

	if (state->base_ns)
		return state->base_ns;

	candidate = now;
	if (candidate >= task_ready_ns(plan))
		candidate -= task_ready_ns(plan);

	prev = __sync_val_compare_and_swap(&state->base_ns, 0, candidate);
	return prev ? prev : candidate;
}

static inline u64 task_abs_start_ns(const struct schedule_task_plan *plan, u64 base_ns)
{
	return base_ns + plan->start_ns;
}

static inline bool task_start_reached(const struct schedule_task_plan *plan, u64 now)
{
	u64 base_ns = get_or_init_schedule_base_ns(plan, now);

	return now >= task_abs_start_ns(plan, base_ns);
}

static inline void enqueue_planned_task(struct task_struct *p,
					 const struct schedule_task_plan *plan,
					 u64 enq_flags)
{
	u64 now = scx_bpf_now();

	if (task_start_reached(plan, now)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | plan->cpu, SCX_SLICE_DFL,
				   enq_flags);
		return;
	}

	scx_bpf_dsq_insert_vtime(p, wait_dsq_id_for_cpu(plan->cpu), SCX_SLICE_DFL,
				 task_abs_start_ns(plan, get_or_init_schedule_base_ns(plan, now)),
				 enq_flags);
	scx_bpf_kick_cpu(plan->cpu, 0);
}

static inline void dispatch_waiting_task(s32 cpu)
{
	struct task_struct *p;
	struct schedule_task_plan plan;
	u64 now;

	p = __COMPAT_scx_bpf_dsq_peek(wait_dsq_id_for_cpu(cpu));
	if (!p)
		return;
	if (!lookup_task_plan(p, &plan))
		return;

	now = scx_bpf_now();
	if (!task_start_reached(&plan, now))
		return;

	scx_bpf_dsq_move_to_local(wait_dsq_id_for_cpu(cpu));
}

s32 BPF_STRUCT_OPS(scheduler_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct schedule_task_plan plan;
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

void BPF_STRUCT_OPS(scheduler_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct schedule_task_plan plan;
	s32 cpu;

	if (lookup_task_plan(p, &plan) && planned_cpu_allowed(p, plan.cpu)) {
		enqueue_planned_task(p, &plan, enq_flags);
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

void BPF_STRUCT_OPS(scheduler_dispatch, s32 cpu, struct task_struct *prev)
{
	if (is_isolated_cpu(cpu)) {
		dispatch_waiting_task(cpu);
		return;
	}

	if (!is_isolated_cpu(cpu))
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(scheduler_running, struct task_struct *p)
{
	struct schedule_task_plan plan;
	struct scheduler_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;

	state = lookup_debug_cpu_state(cpu);
	if (lookup_task_plan(p, &plan) && cpu == (s32)plan.cpu) {
		if (state) {
			state->running_planned_hits++;
			state->perf_apply_hits++;
			state->last_perf = plan.perf_target;
			state->last_plan_task_id = plan.task_id;
			state->last_plan_step_idx = plan.freq_step_idx;
			state->last_plan_freq_khz = plan.freq_khz;
			state->last_plan_pid = p->pid;
			state->last_plan_tgid = p->tgid;
			copy_task_comm(state->last_plan_comm, p->comm);
			record_last_actor(state, SCHEDULER_DEBUG_PLANNED_RUNNING, p);
		}
		set_cpuperf_target(cpu, plan.perf_target);
		return;
	}

	if (state) {
		state->running_unplanned_hits++;
		if (state->last_perf) {
			state->keep_from_running_hits++;
			state->perf_apply_hits++;
			record_last_actor(state, SCHEDULER_DEBUG_UNPLANNED_RUNNING_KEEP, p);
			set_cpuperf_target(cpu, state->last_perf);
			return;
		}

		state->zero_from_running_hits++;
		record_last_actor(state, SCHEDULER_DEBUG_UNPLANNED_RUNNING_ZERO, p);
	}
	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(scheduler_stopping, struct task_struct *p, bool runnable)
{
	struct schedule_task_plan plan;
	struct scheduler_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu) || runnable)
		return;
	if (!lookup_task_plan(p, &plan) || cpu != (s32)plan.cpu)
		return;

	state = lookup_debug_cpu_state(cpu);
	if (state) {
		state->zero_from_stopping_hits++;
		state->last_perf = 0;
		record_last_actor(state, SCHEDULER_DEBUG_STOPPING_ZERO, p);
	}
	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(scheduler_update_idle, s32 cpu, bool idle)
{
	if (!idle || !is_isolated_cpu(cpu))
		return;

	dispatch_waiting_task(cpu);
	{
		struct scheduler_debug_cpu_state *state = lookup_debug_cpu_state(cpu);

		if (state) {
			state->zero_from_idle_hits++;
			record_idle_actor(state);
		}
	}
	set_cpuperf_target(cpu, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scheduler_init)
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
	if (scx_bpf_create_dsq(SHARED_DSQ, -1))
		return -EINVAL;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		if (scx_bpf_create_dsq(wait_dsq_id_for_cpu(ISOLATED_START + i), -1))
			return -EINVAL;
	}

	return 0;
}

void BPF_STRUCT_OPS(scheduler_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(scheduler_ops,
	       .select_cpu		= (void *)scheduler_select_cpu,
	       .enqueue			= (void *)scheduler_enqueue,
	       .dispatch		= (void *)scheduler_dispatch,
	       .running			= (void *)scheduler_running,
	       .stopping		= (void *)scheduler_stopping,
	       .update_idle		= (void *)scheduler_update_idle,
	       .init			= (void *)scheduler_init,
	       .exit			= (void *)scheduler_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "scheduler");
