#include <scx/common.bpf.h>
#include <string.h>


char _license[] SEC("license") = "GPL";

static u64 vtime_now;
static u64 cpu_change_time_now;
static u64 freq_step = 0;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 61);			
} freqs SEC(".maps");

static void set_freq(u32 idx, u32 cpu, u32 freq)
{
	u32 pos = idx * scx_bpf_nr_cpu_ids() + cpu;
	u32 *fr = bpf_map_lookup_elem(&freqs, &pos);
	if (fr)
		(*fr) = freq;
}

void BPF_STRUCT_OPS(dumb_running, struct task_struct *p)
{
	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(dumb_stopping, struct task_struct *p, bool runnable)
{
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

void BPF_STRUCT_OPS(dumb_enable, struct task_struct *p)
{
	u64 now = bpf_ktime_get_ns();
	if (now - cpu_change_time_now > 10000000000ULL) {
		freq_step = 1 - freq_step;

		const struct cpumask* online = scx_bpf_get_online_cpumask();
		
		u32 cpu;
		bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
			if (bpf_cpumask_test_cpu(cpu, online)) {
				bpf_rcu_read_lock();
				scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE * freq_step);
				bpf_rcu_read_unlock();
			}
		}

		scx_bpf_put_cpumask(online);

		cpu_change_time_now = bpf_ktime_get_ns();
	}
	
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(dumb_init)
{
    u32 cpu;
    const struct cpumask* online = scx_bpf_get_online_cpumask();
	
	static const char fmt[] = "MAX: %d"; 
	static const char fmt2[] = "%d "; 
	bpf_trace_printk(fmt, sizeof(fmt), SCX_CPUPERF_ONE);

    bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (bpf_cpumask_test_cpu(cpu, online)) {
			scx_bpf_cpuperf_set(cpu, 0);
			bpf_trace_printk(fmt2, sizeof(fmt2), scx_bpf_cpuperf_cur(cpu));

			set_freq(0, cpu, scx_bpf_cpuperf_cur(cpu));
		}
    }
	bpf_trace_printk("\n", 2);
	
    scx_bpf_put_cpumask(online);
	
	cpu_change_time_now = bpf_ktime_get_ns();
	
	u32 i;
	bpf_for(i, 1, 5) {
		online = scx_bpf_get_online_cpumask();
		bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
			if (bpf_cpumask_test_cpu(cpu, online)) {
				// scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE * i / 5);
				scx_bpf_cpuperf_set(cpu, 0);
				bpf_trace_printk(fmt2, sizeof(fmt2), scx_bpf_cpuperf_cur(cpu));
				set_freq(i, cpu, scx_bpf_cpuperf_cur(cpu));
			}
		}
		bpf_trace_printk("\n", 2);
		scx_bpf_put_cpumask(online);
	}

	set_freq(4, 12, SCX_CPUPERF_ONE);

    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(dumb_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(dumb_ops,
	       .running			= (void *)dumb_running,
	       .stopping		= (void *)dumb_stopping,
	       .enable			= (void *)dumb_enable,
	       .init			= (void *)dumb_init,
	       .exit			= (void *)dumb_exit,
	       .name			= "dumb");
