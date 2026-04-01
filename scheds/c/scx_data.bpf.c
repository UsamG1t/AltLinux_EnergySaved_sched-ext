#include <scx/common.bpf.h>
char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_data only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0
#define ISOLATED_START 6
#define ISOLATED_END 9
#define MIN_FREQ_MHZ 400
#define MAX_FREQ_MHZ 2500
#define LAST_SET_PERF_MAX_CPUS 512

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, LAST_SET_PERF_MAX_CPUS);
} last_set_perf SEC(".maps");

struct task_ctx {
	bool is_var_task;
	bool has_freq_target;
	u16 cpu_start;
	u16 cpu_end;
	u16 freq_mhz;
	u32 perf_target;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool is_pinned(struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
}

static inline bool is_isolated_cpu(s32 cpu)
{
	return cpu >= ISOLATED_START && cpu <= ISOLATED_END;
}

static inline struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

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

	if (!is_dec(c1))
		return false;

	if (c2 != '\0' && c2 != '_')
		return false;

	*value = (c0 - '0') * 10 + (c1 - '0');
	*next = idx + 2;
	return true;
}

static inline bool parse_freq_mhz(const char *name, int idx, u32 *value)
{
	char c0 = name[idx];
	char c1 = name[idx + 1];
	char c2 = name[idx + 2];
	char c3 = name[idx + 3];
	char end = name[idx + 4];

	if (!is_dec(c0) || !is_dec(c1) || !is_dec(c2) || !is_dec(c3))
		return false;
	if (end != '\0')
		return false;

	*value = (c0 - '0') * 1000 + (c1 - '0') * 100 +
		 (c2 - '0') * 10 + (c3 - '0');
	return true;
}

static inline bool parse_var_task_name(const char *name, struct task_ctx *tctx)
{
	u32 cpu_start, cpu_end, freq_mhz = 0;
	u32 perf_target = 0;
	bool has_freq_target = false;
	int next;

	if (name[0] != 'v' || name[1] != 'a' || name[2] != 'r' || name[3] != '_')
		return false;
	if (!parse_cpu_start(name, &cpu_start, &next))
		return false;
	if (!parse_cpu_end(name, next, &cpu_end, &next))
		return false;
	if (cpu_start > cpu_end)
		return false;

	if (name[next] == '\0')
		goto success;
	if (name[next] != '_')
		return false;
	if (!parse_freq_mhz(name, next + 1, &freq_mhz))
		return false;
	if (freq_mhz < MIN_FREQ_MHZ || freq_mhz > MAX_FREQ_MHZ)
		return false;
	if (freq_mhz % 100)
		return false;

	has_freq_target = true;
	perf_target =
		((u64)SCX_CPUPERF_ONE * freq_mhz + MAX_FREQ_MHZ / 2) / MAX_FREQ_MHZ;

success:
	tctx->is_var_task = true;
	tctx->cpu_start = cpu_start;
	tctx->cpu_end = cpu_end;
	tctx->has_freq_target = has_freq_target;
	tctx->freq_mhz = freq_mhz;
	tctx->perf_target = perf_target;
	return true;
}

static inline void set_cpuperf_target(s32 cpu, u32 perf)
{
	u32 key = cpu;
	u32 *last_set = bpf_map_lookup_elem(&last_set_perf, &key);

	if (perf > SCX_CPUPERF_ONE)
		perf = SCX_CPUPERF_ONE;

	if (last_set && *last_set == perf)
		return;

	scx_bpf_cpuperf_set(cpu, perf);
	if (last_set)
		*last_set = perf;
}

s32 BPF_STRUCT_OPS(data_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu;
	s32 new_cpu;
	const struct cpumask *online = scx_bpf_get_online_cpumask();

	tctx = lookup_task_ctx(p);
	if (tctx && tctx->is_var_task) {
		bpf_for(new_cpu, tctx->cpu_start, tctx->cpu_end + 1) {
			if (bpf_cpumask_test_cpu(new_cpu, online) &&
			    is_isolated_cpu(new_cpu)) {
				cpu = new_cpu;
				goto out;
			}
		}
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	if (is_pinned(p) || !is_isolated_cpu(cpu)) {
		if (is_idle) {
			stat_inc(0);	/* count local queueing */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
		goto out;
	}

	/* Default selection landed in the isolated range - find an alternative. */
	s32 alt_cpu = -1;
	s32 idle_cpu = -1;

	bpf_for(new_cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (is_isolated_cpu(new_cpu))
			continue;
		if (!bpf_cpumask_test_cpu(new_cpu, p->cpus_ptr))
			continue;
		if (bpf_cpumask_test_cpu(new_cpu, online)) {
			idle_cpu = new_cpu;
			break;
		}
		if (alt_cpu == -1)
			alt_cpu = new_cpu;
	}

	if (idle_cpu != -1) {
		cpu = idle_cpu;
		is_idle = true;
	} else if (alt_cpu != -1) {
		cpu = alt_cpu;
		is_idle = false;
	} else {
		cpu = ISOLATED_START;
		is_idle = false;
	}

	if (is_idle) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

out:
	scx_bpf_put_cpumask(online);
	return cpu;
}

void BPF_STRUCT_OPS(data_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	stat_inc(1);	/* count global queueing */

	tctx = lookup_task_ctx(p);
	if (tctx && tctx->is_var_task) {
		u32 length = tctx->cpu_end - tctx->cpu_start + 1;
		u32 chosen = tctx->cpu_start + bpf_get_prandom_u32() % length;

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | chosen, SCX_SLICE_DFL,
				   enq_flags);
		return;
	}

	if (is_pinned(p)) {
		unsigned int nr_cpus = scx_bpf_nr_cpu_ids();
		s32 target_cpu = -1;
		s32 i;

		bpf_for(i, 0, nr_cpus) {
			if (bpf_cpumask_test_cpu(i, p->cpus_ptr)) {
				target_cpu = i;
				break;
			}
		}

		if (target_cpu >= 0)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   SCX_SLICE_DFL, enq_flags);
		else
			scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL,
					   enq_flags);
		return;
	}

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(data_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!is_isolated_cpu(cpu))
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(data_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);

	if (is_isolated_cpu(cpu)) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		u32 perf = 0;

		if (tctx && tctx->has_freq_target)
			perf = tctx->perf_target;
		set_cpuperf_target(cpu, perf);
	}

	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(data_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(data_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

void BPF_STRUCT_OPS(data_update_idle, s32 cpu, bool idle)
{
	if (!idle || !is_isolated_cpu(cpu))
		return;

	set_cpuperf_target(cpu, 0);
}

s32 BPF_STRUCT_OPS(data_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->is_var_task = false;
	tctx->has_freq_target = false;
	tctx->cpu_start = 0;
	tctx->cpu_end = 0;
	tctx->freq_mhz = 0;
	tctx->perf_target = 0;

	parse_var_task_name(p->comm, tctx);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(data_init)
{
	u32 cpu;
	const struct cpumask *online = scx_bpf_get_online_cpumask();

	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (bpf_cpumask_test_cpu(cpu, online))
			set_cpuperf_target(cpu, 0);
	}

	scx_bpf_put_cpumask(online);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(data_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(data_ops,
	       .select_cpu		= (void *)data_select_cpu,
	       .enqueue			= (void *)data_enqueue,
	       .dispatch		= (void *)data_dispatch,
	       .running			= (void *)data_running,
	       .stopping		= (void *)data_stopping,
	       .update_idle		= (void *)data_update_idle,
	       .init_task		= (void *)data_init_task,
	       .enable			= (void *)data_enable,
	       .init			= (void *)data_init,
	       .exit			= (void *)data_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "data");
