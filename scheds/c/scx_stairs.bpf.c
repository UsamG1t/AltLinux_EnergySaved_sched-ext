#include <scx/common.bpf.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define NR_FREQ_STEPS 4
#define POLICY_MAX_FREQ_KHZ 1800000
#define STAIRS_COMM_LEN 16

enum stairs_debug_event {
	STAIRS_DEBUG_NONE = 0,
	STAIRS_DEBUG_VAR_RUNNING = 1,
	STAIRS_DEBUG_NONVAR_RUNNING_ZERO = 2,
	STAIRS_DEBUG_STOPPING_ZERO = 3,
	STAIRS_DEBUG_IDLE_ZERO = 4,
};

static const u32 stairs_freq_steps_khz[NR_FREQ_STEPS] = {
	400000,
	900000,
	1400000,
	1800000,
};

static const u32 stairs_perf_steps[NR_FREQ_STEPS] = {
	48,
	224,
	384,
	576,
};

struct stairs_debug_cpu_state {
	u64 running_var_hits;
	u64 running_nonvar_hits;
	u64 perf_apply_hits;
	u64 zero_from_running_hits;
	u64 zero_from_stopping_hits;
	u64 zero_from_idle_hits;
	u32 last_event;
	u32 last_perf;
	u32 last_var_step_idx;
	u32 last_var_freq_khz;
	u32 last_var_pid;
	u32 last_var_tgid;
	char last_var_comm[STAIRS_COMM_LEN];
	u32 last_actor_pid;
	u32 last_actor_tgid;
	char last_actor_comm[STAIRS_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct stairs_debug_cpu_state));
	__uint(max_entries, NR_ISOLATED_CPUS);
} debug_cpu_state SEC(".maps");

struct var_task_spec {
	bool valid;
	bool has_freq_target;
	u16 cpu_start;
	u16 cpu_end;
	u16 freq_step_idx;
	u32 target_freq_khz;
	u32 perf_target;
};

static inline bool is_dec(char c)
{
	return c >= '0' && c <= '9';
}

static inline bool parse_cpu_start(const char *name, u32 *value, int *next)
{
	char c0 = name[4];
	char c1 = name[5];
	char c2 = name[6];

	if (!is_dec(c0))
		return false;

	if (c1 == '_') {
		*value = c0 - '0';
		*next = 6;
		return true;
	}

	if (!is_dec(c1) || c2 != '_')
		return false;

	*value = (c0 - '0') * 10 + (c1 - '0');
	*next = 7;
	return true;
}

static inline bool parse_cpu_end(const char *name, int idx, u32 *value, int *next)
{
	char c0 = name[idx];
	char c1 = name[idx + 1];
	char c2 = name[idx + 2];

	if (!is_dec(c0))
		return false;

	if (c1 == '\0' || c1 == '_') {
		*value = c0 - '0';
		*next = idx + 1;
		return true;
	}

	if (!is_dec(c1) || (c2 != '\0' && c2 != '_'))
		return false;

	*value = (c0 - '0') * 10 + (c1 - '0');
	*next = idx + 2;
	return true;
}

static inline bool lookup_freq_step(u32 step_idx, u32 *freq_khz,
				    u32 *perf_target)
{
	switch (step_idx) {
	case 1:
		*freq_khz = stairs_freq_steps_khz[0];
		*perf_target = stairs_perf_steps[0];
		return true;
	case 2:
		*freq_khz = stairs_freq_steps_khz[1];
		*perf_target = stairs_perf_steps[1];
		return true;
	case 3:
		*freq_khz = stairs_freq_steps_khz[2];
		*perf_target = stairs_perf_steps[2];
		return true;
	case 4:
		*freq_khz = stairs_freq_steps_khz[3];
		*perf_target = stairs_perf_steps[3];
		return true;
	default:
		return false;
	}
}

static inline bool parse_freq_step(const char *name, int idx, u32 *value)
{
	char c0 = name[idx];
	char c1 = name[idx + 1];

	if (!is_dec(c0))
		return false;
	if (c1 != '\0')
		return false;

	*value = c0 - '0';
	return true;
}

static inline bool parse_var_task_name(const char *name, struct var_task_spec *spec)
{
	u32 cpu_start;
	u32 cpu_end;
	u32 step_idx = 0;
	u32 freq_khz = 0;
	u32 perf_target = 0;
	int next;

	spec->valid = false;
	spec->has_freq_target = false;
	spec->cpu_start = 0;
	spec->cpu_end = 0;
	spec->freq_step_idx = 0;
	spec->target_freq_khz = 0;
	spec->perf_target = 0;

	if (name[0] != 'v' || name[1] != 'a' || name[2] != 'r' || name[3] != '_')
		return false;
	if (!parse_cpu_start(name, &cpu_start, &next))
		return false;
	if (!parse_cpu_end(name, next, &cpu_end, &next))
		return false;
	if (name[next] != '\0' && name[next] != '_')
		return false;
	if (cpu_start > cpu_end)
		return false;
	if (name[next] == '_') {
		if (!parse_freq_step(name, next + 1, &step_idx))
			return false;
		if (!lookup_freq_step(step_idx, &freq_khz, &perf_target))
			return false;
		spec->has_freq_target = true;
		spec->freq_step_idx = step_idx;
		spec->target_freq_khz = freq_khz;
		spec->perf_target = perf_target;
	}

	spec->valid = true;
	spec->cpu_start = cpu_start;
	spec->cpu_end = cpu_end;
	return true;
}

static inline bool is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
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

static inline struct stairs_debug_cpu_state *lookup_debug_cpu_state(s32 cpu)
{
	u32 key = isolated_cpu_slot(cpu);

	if ((s32)key < 0)
		return NULL;
	return bpf_map_lookup_elem(&debug_cpu_state, &key);
}

static inline void copy_task_comm(char dst[STAIRS_COMM_LEN],
				  const char src[STAIRS_COMM_LEN])
{
	__builtin_memcpy(dst, src, STAIRS_COMM_LEN);
}

static inline void clear_task_comm(char dst[STAIRS_COMM_LEN])
{
	__builtin_memset(dst, 0, STAIRS_COMM_LEN);
}

static inline void record_last_actor(struct stairs_debug_cpu_state *state,
				     enum stairs_debug_event event,
				     const struct task_struct *p)
{
	state->last_event = event;
	state->last_actor_pid = p->pid;
	state->last_actor_tgid = p->tgid;
	copy_task_comm(state->last_actor_comm, p->comm);
}

static inline void record_idle_actor(struct stairs_debug_cpu_state *state)
{
	state->last_event = STAIRS_DEBUG_IDLE_ZERO;
	state->last_actor_pid = 0;
	state->last_actor_tgid = 0;
	clear_task_comm(state->last_actor_comm);
}

static inline bool can_run_on_isolated_cpu(const struct task_struct *p,
					   const struct cpumask *online,
					   const struct var_task_spec *spec,
					   s32 cpu)
{
	if (cpu < spec->cpu_start || cpu > spec->cpu_end)
		return false;
	if (!bpf_cpumask_test_cpu(cpu, online))
		return false;
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;
	return true;
}

static inline s32 first_allowed_isolated_cpu(const struct task_struct *p,
					     const struct var_task_spec *spec)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	s32 chosen = -1;
	int i;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		s32 cpu = ISOLATED_START + i;

		if (!can_run_on_isolated_cpu(p, online, spec, cpu))
			continue;
		chosen = cpu;
		break;
	}

	scx_bpf_put_cpumask(online);
	return chosen;
}

static inline s32 pick_allowed_isolated_cpu(const struct task_struct *p,
					    const struct var_task_spec *spec)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	s32 chosen = -1;
	u32 start = bpf_get_prandom_u32() % NR_ISOLATED_CPUS;
	int i;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		s32 cpu = ISOLATED_START + ((start + i) % NR_ISOLATED_CPUS);

		if (!can_run_on_isolated_cpu(p, online, spec, cpu))
			continue;
		chosen = cpu;
		break;
	}

	scx_bpf_put_cpumask(online);
	return chosen;
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

static inline void set_cpuperf_target(s32 cpu, u32 perf)
{
	if (perf > SCX_CPUPERF_ONE)
		perf = SCX_CPUPERF_ONE;

	scx_bpf_cpuperf_set(cpu, perf);
}

s32 BPF_STRUCT_OPS(stairs_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct var_task_spec spec;
	bool is_idle = false;
	s32 cpu;

	if (parse_var_task_name(p->comm, &spec)) {
		cpu = first_allowed_isolated_cpu(p, &spec);
		if (cpu >= 0)
			return cpu;
	}

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

static inline s32 pinned_cpu(const struct task_struct *p)
{
	return scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
}

void BPF_STRUCT_OPS(stairs_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct var_task_spec spec;
	s32 target_cpu;

	if (parse_var_task_name(p->comm, &spec)) {
		target_cpu = pick_allowed_isolated_cpu(p, &spec);
		if (target_cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   SCX_SLICE_DFL, enq_flags);
			return;
		}
	}

	if (is_pinned(p)) {
		target_cpu = pinned_cpu(p);
		if (target_cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   SCX_SLICE_DFL, enq_flags);
			return;
		}
	}

	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(stairs_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!is_isolated_cpu(cpu))
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(stairs_running, struct task_struct *p)
{
	struct var_task_spec spec;
	struct stairs_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;

	state = lookup_debug_cpu_state(cpu);
	if (parse_var_task_name(p->comm, &spec) && spec.has_freq_target) {
		if (state) {
			state->running_var_hits++;
			state->perf_apply_hits++;
			state->last_perf = spec.perf_target;
			state->last_var_step_idx = spec.freq_step_idx;
			state->last_var_freq_khz = spec.target_freq_khz;
			state->last_var_pid = p->pid;
			state->last_var_tgid = p->tgid;
			copy_task_comm(state->last_var_comm, p->comm);
			record_last_actor(state, STAIRS_DEBUG_VAR_RUNNING, p);
		}
		set_cpuperf_target(cpu, spec.perf_target);
		return;
	}

	if (state) {
		state->running_nonvar_hits++;
		state->zero_from_running_hits++;
		state->last_perf = 0;
		record_last_actor(state, STAIRS_DEBUG_NONVAR_RUNNING_ZERO, p);
	}
	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(stairs_stopping, struct task_struct *p, bool runnable)
{
	struct stairs_debug_cpu_state *state;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;
	if (runnable)
		return;

	state = lookup_debug_cpu_state(cpu);
	if (state) {
		state->zero_from_stopping_hits++;
		state->last_perf = 0;
		record_last_actor(state, STAIRS_DEBUG_STOPPING_ZERO, p);
	}
	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(stairs_update_idle, s32 cpu, bool idle)
{
	struct stairs_debug_cpu_state *state;

	if (!idle || !is_isolated_cpu(cpu))
		return;

	state = lookup_debug_cpu_state(cpu);
	if (state) {
		state->zero_from_idle_hits++;
		state->last_perf = 0;
		record_idle_actor(state);
	}
	set_cpuperf_target(cpu, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(stairs_init)
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

void BPF_STRUCT_OPS(stairs_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(stairs_ops,
	       .select_cpu		= (void *)stairs_select_cpu,
	       .enqueue			= (void *)stairs_enqueue,
	       .dispatch		= (void *)stairs_dispatch,
	       .running			= (void *)stairs_running,
	       .stopping		= (void *)stairs_stopping,
	       .update_idle		= (void *)stairs_update_idle,
	       .init			= (void *)stairs_init,
	       .exit			= (void *)stairs_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "stairs");
