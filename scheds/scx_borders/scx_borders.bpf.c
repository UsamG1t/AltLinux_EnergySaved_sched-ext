#include <scx/common.bpf.h>

#include "scx_borders_sched.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define TRACE_CB(fmt, args...) bpf_printk("scx_borders " fmt, ##args)

#define SHARED_DSQ 0
#define WAIT_DSQ_BASE 0x1000
#define ISOLATED_START 0
#define ISOLATED_END 1
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)

struct borders_task_name {
	u32 task_id;
};

struct borders_runtime_state {
	u64 base_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BORDERS_MAX_TASKS);
	__type(key, __u32);
	__type(value, struct borders_task_plan);
} task_plans SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct borders_control);
} borders_control SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct borders_runtime_state);
} borders_runtime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_ISOLATED_CPUS);
	__type(key, __u32);
	__type(value, struct borders_debug_cpu_state);
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

static inline struct borders_debug_cpu_state *lookup_borders_debug_cpu_state(s32 cpu)
{
	s32 slot = isolated_cpu_slot(cpu);
	u32 key;

	if (slot < 0)
		return NULL;

	key = (u32)slot;
	return bpf_map_lookup_elem(&debug_cpu_state, &key);
}

static inline void copy_task_comm(char dst[BORDERS_TASK_COMM_LEN],
				  const char src[BORDERS_TASK_COMM_LEN])
{
	__builtin_memcpy(dst, src, BORDERS_TASK_COMM_LEN);
}

static inline void clear_task_comm(char dst[BORDERS_TASK_COMM_LEN])
{
	__builtin_memset(dst, 0, BORDERS_TASK_COMM_LEN);
}

static inline void record_last_actor(struct borders_debug_cpu_state *state,
				     enum borders_debug_event event,
				     const struct task_struct *p)
{
	state->last_event = event;
	state->last_actor_pid = p->pid;
	state->last_actor_tgid = p->tgid;
	copy_task_comm(state->last_actor_comm, p->comm);
}

static inline void record_idle_actor(struct borders_debug_cpu_state *state)
{
	state->last_event = BORDERS_DEBUG_IDLE_ZERO;
	state->last_actor_pid = 0;
	state->last_actor_tgid = 0;
	clear_task_comm(state->last_actor_comm);
}

static inline bool parse_borders_task_name(const char *name,
					 struct borders_task_name *task_name)
{
	u32 task_id = 0;
	bool seen_id = false;
	int i;

	if (name[0] != 't' || name[1] != 'a' || name[2] != 's' ||
	    name[3] != 'k')
		return false;

	#pragma unroll
	for (i = 4; i < BORDERS_TASK_COMM_LEN; i++) {
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
				    struct borders_task_plan *plan)
{
	struct borders_task_name task_name;
	struct borders_task_plan *map_plan;

	if (!parse_borders_task_name(p->comm, &task_name))
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

static inline void request_frequency_border(s32 cpu, u32 freq_khz)
{
	(void)cpu;
	(void)freq_khz;
}

static inline u64 wait_dsq_id_for_cpu(s32 cpu)
{
	return WAIT_DSQ_BASE + (u64)(cpu - ISOLATED_START);
}

static inline u64 task_ready_ns(const struct borders_task_plan *plan)
{
	return (u64)plan->ready_ms * 1000000ULL;
}

static inline u64 get_or_init_schedule_base_ns(const struct borders_task_plan *plan,
					       u64 now)
{
	struct borders_runtime_state *state;
	u64 candidate;
	u64 prev;
	u32 key = 0;

	state = bpf_map_lookup_elem(&borders_runtime, &key);
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

static inline u64 task_abs_start_ns(const struct borders_task_plan *plan, u64 base_ns)
{
	return base_ns + plan->start_ns;
}

static inline bool task_start_reached(const struct borders_task_plan *plan, u64 now)
{
	u64 base_ns = get_or_init_schedule_base_ns(plan, now);

	return now >= task_abs_start_ns(plan, base_ns);
}

static inline void enqueue_planned_task(struct task_struct *p,
					 const struct borders_task_plan *plan,
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
	struct borders_task_plan plan;
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

s32 BPF_STRUCT_OPS(borders_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct borders_task_plan plan;
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

void BPF_STRUCT_OPS(borders_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct borders_task_plan plan;
	s32 cpu;

	if (lookup_task_plan(p, &plan) && planned_cpu_allowed(p, plan.cpu)) {
		TRACE_CB("cb=enqueue case=plan pid=%d task=%u cpu=%u step=%u freq=%u",
			 p->pid, plan.task_id, plan.cpu, plan.freq_step_idx,
			 plan.freq_khz);
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

void BPF_STRUCT_OPS(borders_dispatch, s32 cpu, struct task_struct *prev)
{
	if (is_isolated_cpu(cpu)) {
		dispatch_waiting_task(cpu);
		return;
	}

	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(borders_running, struct task_struct *p)
{
	struct borders_task_plan plan;
	struct borders_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;

	state = lookup_borders_debug_cpu_state(cpu);
	if (lookup_task_plan(p, &plan) && cpu == (s32)plan.cpu) {
		if (!state || state->last_event != BORDERS_DEBUG_PLANNED_RUNNING ||
		    state->last_plan_task_id != plan.task_id ||
		    state->last_plan_freq_khz != plan.freq_khz ||
		    state->last_actor_pid != p->pid) {
			TRACE_CB("cb=running case=plan cpu=%d pid=%d task=%u freq=%u",
				 cpu, p->pid, plan.task_id, plan.freq_khz);
		}
		if (state) {
			state->running_planned_hits++;
			state->border_apply_hits++;
			state->last_border_khz = plan.freq_khz;
			state->last_plan_task_id = plan.task_id;
			state->last_plan_step_idx = plan.freq_step_idx;
			state->last_plan_freq_khz = plan.freq_khz;
			state->last_plan_pid = p->pid;
			state->last_plan_tgid = p->tgid;
			copy_task_comm(state->last_plan_comm, p->comm);
			record_last_actor(state, BORDERS_DEBUG_PLANNED_RUNNING, p);
		}
		request_frequency_border(cpu, plan.freq_khz);
		return;
	}

	if (state) {
		state->running_unplanned_hits++;
		if (state->last_plan_freq_khz) {
			if (state->last_event != BORDERS_DEBUG_UNPLANNED_RUNNING_KEEP ||
			    state->last_actor_pid != p->pid) {
				TRACE_CB("cb=running case=keep cpu=%d pid=%d freq=%u",
					 cpu, p->pid, state->last_plan_freq_khz);
			}
			state->keep_from_running_hits++;
			state->border_apply_hits++;
			state->last_border_khz = state->last_plan_freq_khz;
			record_last_actor(state, BORDERS_DEBUG_UNPLANNED_RUNNING_KEEP, p);
			request_frequency_border(cpu, state->last_plan_freq_khz);
			return;
		}

		state->zero_from_running_hits++;
		state->last_border_khz = 0;
		record_last_actor(state, BORDERS_DEBUG_UNPLANNED_RUNNING_ZERO, p);
	}
	if (!state || state->last_event != BORDERS_DEBUG_UNPLANNED_RUNNING_ZERO ||
	    state->last_actor_pid != p->pid)
		TRACE_CB("cb=running case=zero cpu=%d pid=%d", cpu, p->pid);
	request_frequency_border(cpu, 0);
}

void BPF_STRUCT_OPS(borders_stopping, struct task_struct *p, bool runnable)
{
	struct borders_task_plan plan;
	struct borders_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu) || runnable)
		return;
	if (!lookup_task_plan(p, &plan) || cpu != (s32)plan.cpu)
		return;

	state = lookup_borders_debug_cpu_state(cpu);
	if (!state || state->last_event != BORDERS_DEBUG_STOPPING_ZERO ||
	    state->last_actor_pid != p->pid)
		TRACE_CB("cb=stopping case=planned_done cpu=%d pid=%d task=%u",
			 cpu, p->pid, plan.task_id);
	if (state) {
		state->zero_from_stopping_hits++;
		state->last_border_khz = 0;
		record_last_actor(state, BORDERS_DEBUG_STOPPING_ZERO, p);
	}
	request_frequency_border(cpu, 0);
}

void BPF_STRUCT_OPS(borders_update_idle, s32 cpu, bool idle)
{
	if (!idle || !is_isolated_cpu(cpu))
		return;

	dispatch_waiting_task(cpu);
	{
		struct borders_debug_cpu_state *state = lookup_borders_debug_cpu_state(cpu);

		if (state) {
			if (state->last_event != BORDERS_DEBUG_IDLE_ZERO)
				TRACE_CB("cb=update_idle case=idle cpu=%d", cpu);
			state->zero_from_idle_hits++;
			state->last_border_khz = 0;
			record_idle_actor(state);
		}
	}
	request_frequency_border(cpu, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(borders_init)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	int i;

	TRACE_CB("cb=init cpus=%d-%d", ISOLATED_START, ISOLATED_END);

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		u32 cpu = ISOLATED_START + i;

		if (bpf_cpumask_test_cpu(cpu, online))
			request_frequency_border(cpu, 0);
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

void BPF_STRUCT_OPS(borders_exit, struct scx_exit_info *ei)
{
	TRACE_CB("cb=exit");
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(borders_ops,
	       .select_cpu		= (void *)borders_select_cpu,
	       .enqueue			= (void *)borders_enqueue,
	       .dispatch		= (void *)borders_dispatch,
	       .running			= (void *)borders_running,
	       .stopping		= (void *)borders_stopping,
	       .update_idle		= (void *)borders_update_idle,
	       .init			= (void *)borders_init,
	       .exit			= (void *)borders_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "borders");
