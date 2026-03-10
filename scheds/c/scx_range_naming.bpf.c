#include <scx/common.bpf.h>
#include <string.h>


char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
static u64 cpu_change_time_now;
static u64 freq_step = 10;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_range_naming only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0
#define ISOLATED_START 6
#define ISOLATED_END 9

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, 12);
} valid_cpuperf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [Tries, misses] */
} checks SEC(".maps");

static void check_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&checks, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool is_pinned(struct task_struct* p) {
	return p->nr_cpus_allowed == 1;
}

s32 BPF_STRUCT_OPS(range_naming_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	const struct cpumask* online = scx_bpf_get_online_cpumask();
	s32 new_cpu;
	
	char* name = p->comm;
	if (!strncmp("var", name, 3)) {
		s32 cpu_start = name[4] - '0';
		s32 cpu_end = name[6] - '0';
		
		bpf_for(new_cpu, cpu_start, cpu_end + 1) {
			if (bpf_cpumask_test_cpu(new_cpu, online) && new_cpu >= ISOLATED_START && new_cpu <= ISOLATED_END) {
                cpu = new_cpu;
                goto out;
			}
		}
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	
	// if (is_pinned(p) || cpu != ISOLATED) {
	if (is_pinned(p) || cpu < ISOLATED_START || cpu > ISOLATED_END) {
		if (is_idle) {
			stat_inc(0);	/* count local queueing */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
        goto out;
	}

	// -------------------------------------------------
	/* Стандартный выбор дал список изолированных – ищем альтернативу */
	s32 alt_cpu = -1;
	s32 idle_cpu = -1;

	// const struct cpumask* online = scx_bpf_get_online_cpumask();
	
	// s32 new_cpu;
	bpf_for(new_cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (new_cpu >= ISOLATED_START && new_cpu <= ISOLATED_END) continue;
		if (!bpf_cpumask_test_cpu(new_cpu, p->cpus_ptr)) continue;
		if (bpf_cpumask_test_cpu(new_cpu, online)) {
			idle_cpu = new_cpu;
			break;
		}
		if (alt_cpu == -1) alt_cpu = new_cpu;
	}

	if (idle_cpu != -1) {
		cpu = idle_cpu;
		is_idle = true;
	} else if (alt_cpu != -1) {
		cpu = alt_cpu;
		is_idle = false;
	} else {
		/* Нет альтернатив – придётся использовать изолированный диапазон */
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
	// -------------------------------------------------------
}

void BPF_STRUCT_OPS(range_naming_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	char* name = p->comm;
	if (!strncmp("var", name, 3)) {
		check_inc(0);
		s32 cpu_start = name[4] - '0';
		s32 cpu_end = name[6] - '0';
		u32 length = cpu_end - cpu_start + 1;
		
		const struct cpumask* online = scx_bpf_get_online_cpumask();
        u32 cpu;
        u32 chosen = -1;
		u8 flag = 0;

		bpf_for(cpu, cpu_start, cpu_end + 1) {
			if (!bpf_cpumask_test_cpu(cpu, online)) {
				continue;
			}
			
			u8* valid = bpf_map_lookup_elem(&valid_cpuperf, &cpu);
			if (valid && *valid) {
				chosen = cpu;
				flag = 0xFF;
				break;
			}
		}
		
		if (chosen == -1) {
			chosen = cpu_start + bpf_get_prandom_u32() % length;
		}
		
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | chosen, SCX_SLICE_DFL, enq_flags);	
		
		if (flag == 0xFF) {
			scx_bpf_cpuperf_set(chosen, SCX_CPUPERF_ONE / 2);
		} else {
			check_inc(1);
		}
		
        scx_bpf_put_cpumask(online);
		return;
	}
	
	// ---------------------------------------------------------------
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
	
        if (target_cpu >= 0) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, enq_flags);
        } else {
            /* Если не нашли (редкий случай) – отправим в общую очередь */
            scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
        }
        return;
    }
    
	/* Все остальные задачи идут в общую очередь SHARED_DSQ */
	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	}
	// -----------------------------------------
}

void BPF_STRUCT_OPS(range_naming_dispatch, s32 cpu, struct task_struct *prev)
{
	
	if (cpu < ISOLATED_START || cpu > ISOLATED_END) {
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
	}
}

void BPF_STRUCT_OPS(range_naming_running, struct task_struct *p)
{
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

void BPF_STRUCT_OPS(range_naming_stopping, struct task_struct *p, bool runnable)
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

void BPF_STRUCT_OPS(range_naming_enable, struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	if (now - cpu_change_time_now > 10000000000) {
		freq_step -= 1;
		
		if (!freq_step) {
			return;
		}

		const struct cpumask* online = scx_bpf_get_online_cpumask();
		
		u32 cpu;
		bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
			if (bpf_cpumask_test_cpu(cpu, online)) {
				scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE / freq_step);
				u8 valid = (scx_bpf_cpuperf_cur(cpu) == SCX_CPUPERF_ONE / freq_step);
				bpf_map_update_elem(&valid_cpuperf, &cpu, &valid, BPF_ANY);
			}
		}

		scx_bpf_put_cpumask(online);

		cpu_change_time_now = bpf_ktime_get_ns();
	}
	
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(range_naming_init)
{
    u32 cpu;
    const struct cpumask* online = scx_bpf_get_online_cpumask();

    bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
        if (bpf_cpumask_test_cpu(cpu, online)) {
			scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE / 10);
			u8 valid = (scx_bpf_cpuperf_cur(cpu) == SCX_CPUPERF_ONE / 10);
			bpf_map_update_elem(&valid_cpuperf, &cpu, &valid, BPF_ANY);
		}
    }

    scx_bpf_put_cpumask(online);

	cpu_change_time_now = bpf_ktime_get_ns();

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(range_naming_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(range_naming_ops,
	       .select_cpu		= (void *)range_naming_select_cpu,
	       .enqueue			= (void *)range_naming_enqueue,
	       .dispatch		= (void *)range_naming_dispatch,
	       .running			= (void *)range_naming_running,
	       .stopping		= (void *)range_naming_stopping,
	       .enable			= (void *)range_naming_enable,
	       .init			= (void *)range_naming_init,
	       .exit			= (void *)range_naming_exit,
	       .name			= "range_naming");
