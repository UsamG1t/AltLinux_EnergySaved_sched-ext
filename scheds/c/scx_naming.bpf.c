#include <scx/common.bpf.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_naming only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0
#define ISOLATED 11


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

static inline bool is_pinned(struct task_struct* p) {
	return (p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1;
}

s32 BPF_STRUCT_OPS(naming_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	char* name = p->comm;
	if (!strncmp("var", name, 3)) {
		return 11;
	}

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	
	if (is_pinned(p) || cpu != ISOLATED) {
	// if (cpu != ISOLATED) {
		if (is_idle) {
			stat_inc(0);	/* count local queueing */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
		
		return cpu;
	}

	// -------------------------------------------------
	/* Стандартный выбор дал 11 – ищем альтернативу */
	s32 alt_cpu = -1;
	s32 idle_cpu = -1;

	const struct cpumask* online = scx_bpf_get_online_cpumask();
	
	s32 new_cpu;
	bpf_for(new_cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (new_cpu == ISOLATED) continue;
		if (!bpf_cpumask_test_cpu(new_cpu, p->cpus_ptr)) continue;
		if (bpf_cpumask_test_cpu(new_cpu, online)) {
			idle_cpu = new_cpu;
			break;
		}
		if (alt_cpu == -1) alt_cpu = new_cpu;
	}

	scx_bpf_put_cpumask(online);

	if (idle_cpu != -1) {
		cpu = idle_cpu;
		is_idle = true;
	} else if (alt_cpu != -1) {
		cpu = alt_cpu;
		is_idle = false;
	} else {
		/* Нет альтернатив – придётся использовать 11 */
		cpu = 11;
		is_idle = false;
	}

	if (is_idle) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
	// -------------------------------------------------------
}

void BPF_STRUCT_OPS(naming_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	char* name = p->comm;
	if (!strncmp("var", name, 3)) {
		// if (fifo_sched) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | ISOLATED, SCX_SLICE_DFL, enq_flags);	
		// } else {
		// 	u64 vtime = p->scx.dsq_vtime;
		
		// 	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
		// 		vtime = vtime_now - SCX_SLICE_DFL;
			
		// 	scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL_ON | ISOLATED, SCX_SLICE_DFL, vtime,
		// 		enq_flags);
		// }
		
		scx_bpf_kick_cpu(ISOLATED, SCX_KICK_PREEMPT);
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
			/* Вставляем прямо в локальную очередь нужного CPU */
			// if (fifo_sched) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, enq_flags);
			// } else {
			// 	u64 vtime = p->scx.dsq_vtime;
			// 	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			// 		vtime = vtime_now - SCX_SLICE_DFL;
			// 	scx_bpf_dsq_insert_vtime(p, SCX_DSQ_LOCAL_ON | target_cpu, SCX_SLICE_DFL, vtime, enq_flags);
			// }
			return;
		}
		/* Если не нашли (редкий случай) – отправим в общую очередь */
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

void BPF_STRUCT_OPS(naming_dispatch, s32 cpu, struct task_struct *prev)
{
	
	if (cpu != 11) {
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
	}
}

void BPF_STRUCT_OPS(naming_running, struct task_struct *p)
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

void BPF_STRUCT_OPS(naming_stopping, struct task_struct *p, bool runnable)
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

void BPF_STRUCT_OPS(naming_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(naming_init)
{
	s32 cpu;
	bpf_for(cpu, 0, 11) {
		scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
	}
	
	scx_bpf_cpuperf_set(11, 0);

    return scx_bpf_create_dsq(SHARED_DSQ, -1);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(naming_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(naming_ops,
	       .select_cpu		= (void *)naming_select_cpu,
	       .enqueue			= (void *)naming_enqueue,
	       .dispatch		= (void *)naming_dispatch,
	       .running			= (void *)naming_running,
	       .stopping		= (void *)naming_stopping,
	       .enable			= (void *)naming_enable,
	       .init			= (void *)naming_init,
	       .exit			= (void *)naming_exit,
	       .name			= "naming");
