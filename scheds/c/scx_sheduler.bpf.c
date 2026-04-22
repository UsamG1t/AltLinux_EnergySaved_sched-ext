#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define ISOLATED_START 6
#define ISOLATED_END 9
#define NR_ISOLATED_CPUS (ISOLATED_END - ISOLATED_START + 1)
#define NR_FREQ_STEPS 9

static const u32 sheduler_freq_steps_khz[NR_FREQ_STEPS] = {
	400000,
	600000,
	800000,
	900000,
	1100000,
	1300000,
	1500000,
	1600000,
	1800000,
};

static const u32 sheduler_perf_steps[NR_FREQ_STEPS] = {
	48,
	165,
	256,
	288,
	352,
	416,
	480,
	512,
	576,
};

struct var_task_spec {
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

static inline bool is_isolated_cpu(s32 cpu)
{
	return cpu >= ISOLATED_START && cpu <= ISOLATED_END;
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

// static inline bool lookup_freq_step(u32 step_idx, u32 *freq_khz, u32 *perf_target)
// {
// 	switch (step_idx) {
// 	case 1:
// 		*freq_khz = sheduler_freq_steps_khz[0];
// 		*perf_target = sheduler_perf_steps[0];
// 		return true;
// 	case 2:
// 		*freq_khz = sheduler_freq_steps_khz[1];
// 		*perf_target = sheduler_perf_steps[1];
// 		return true;
// 	case 3:
// 		*freq_khz = sheduler_freq_steps_khz[2];
// 		*perf_target = sheduler_perf_steps[2];
// 		return true;
// 	case 4:
// 		*freq_khz = sheduler_freq_steps_khz[3];
// 		*perf_target = sheduler_perf_steps[3];
// 		return true;
// 	case 5:
// 		*freq_khz = sheduler_freq_steps_khz[4];
// 		*perf_target = sheduler_perf_steps[4];
// 		return true;
// 	case 6:
// 		*freq_khz = sheduler_freq_steps_khz[5];
// 		*perf_target = sheduler_perf_steps[5];
// 		return true;
// 	case 7:
// 		*freq_khz = sheduler_freq_steps_khz[6];
// 		*perf_target = sheduler_perf_steps[6];
// 		return true;
// 	case 8:
// 		*freq_khz = sheduler_freq_steps_khz[7];
// 		*perf_target = sheduler_perf_steps[7];
// 		return true;
// 	case 9:
// 		*freq_khz = sheduler_freq_steps_khz[8];
// 		*perf_target = sheduler_perf_steps[8];
// 		return true;
// 	default:
// 		return false;
// 	}
// }

static inline bool lookup_freq_step(u32 step_idx, u32 *freq_khz, u32 *perf_target)
{
	if (step_idx >= 1 && step_idx <= 9) {
		*freq_khz = sheduler_freq_steps_khz[0];
		*perf_target = sheduler_perf_steps[0];
		return true;
	}
	return false;
}


static inline bool parse_var_task_name(const char *name, struct var_task_spec *spec)
{
	u32 cpu_start;
	u32 cpu_end;
	u32 step_idx;
	int next;

	__builtin_memset(spec, 0, sizeof(*spec));

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

	spec->cpu_start = cpu_start;
	spec->cpu_end = cpu_end;

	if (name[next] == '\0')
		return true;

	if (!parse_freq_step(name, next + 1, &step_idx))
		return false;
	if (!lookup_freq_step(step_idx, &spec->target_freq_khz, &spec->perf_target))
		return false;

	spec->has_freq_target = true;
	spec->freq_step_idx = step_idx;
	return true;
}

static inline bool is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
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
	s32 cpu = -1;
	int i;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		s32 candidate = ISOLATED_START + i;

		if (!can_run_on_isolated_cpu(p, online, spec, candidate))
			continue;
		cpu = candidate;
		break;
	}

	scx_bpf_put_cpumask(online);
	return cpu;
}

static inline s32 pick_allowed_isolated_cpu(const struct task_struct *p,
					    const struct var_task_spec *spec)
{
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	s32 cpu = -1;
	u32 start = bpf_get_prandom_u32() % NR_ISOLATED_CPUS;
	int i;

	#pragma unroll
	for (i = 0; i < NR_ISOLATED_CPUS; i++) {
		s32 candidate = ISOLATED_START + ((start + i) % NR_ISOLATED_CPUS);

		if (!can_run_on_isolated_cpu(p, online, spec, candidate))
			continue;
		cpu = candidate;
		break;
	}

	scx_bpf_put_cpumask(online);
	return cpu;
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

s32 BPF_STRUCT_OPS(sheduler_select_cpu, struct task_struct *p, s32 prev_cpu,
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

void BPF_STRUCT_OPS(sheduler_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct var_task_spec spec;
	s32 cpu;

	if (parse_var_task_name(p->comm, &spec)) {
		cpu = pick_allowed_isolated_cpu(p, &spec);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   SCX_SLICE_DFL, enq_flags);
			return;
		}
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

void BPF_STRUCT_OPS(sheduler_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!is_isolated_cpu(cpu))
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(sheduler_running, struct task_struct *p)
{
	struct var_task_spec spec;
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu))
		return;

	if (parse_var_task_name(p->comm, &spec) && spec.has_freq_target) {
		set_cpuperf_target(cpu, spec.perf_target);
		return;
	}

	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(sheduler_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);

	if (!is_isolated_cpu(cpu) || runnable)
		return;

	set_cpuperf_target(cpu, 0);
}

void BPF_STRUCT_OPS(sheduler_update_idle, s32 cpu, bool idle)
{
	if (!idle || !is_isolated_cpu(cpu))
		return;

	set_cpuperf_target(cpu, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sheduler_init)
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

void BPF_STRUCT_OPS(sheduler_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(sheduler_ops,
	       .select_cpu		= (void *)sheduler_select_cpu,
	       .enqueue			= (void *)sheduler_enqueue,
	       .dispatch		= (void *)sheduler_dispatch,
	       .running			= (void *)sheduler_running,
	       .stopping		= (void *)sheduler_stopping,
	       .update_idle		= (void *)sheduler_update_idle,
	       .init			= (void *)sheduler_init,
	       .exit			= (void *)sheduler_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "sheduler");
