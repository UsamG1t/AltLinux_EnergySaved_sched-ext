#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile s32 target_cpu = 2;
const volatile u32 target_perf = SCX_CPUPERF_ONE;

UEI_DEFINE(uei);

static __always_inline void set_target_cpuperf_unlocked(void)
{
    scx_bpf_cpuperf_set(target_cpu, target_perf);
}

static __always_inline void set_target_cpuperf_if_local(void)
{
    s32 cpu = bpf_get_smp_processor_id();

    if (cpu == target_cpu)
        scx_bpf_cpuperf_set(cpu, target_perf);
}

s32 BPF_STRUCT_OPS(fixed_select_cpu,
                   struct task_struct *p,
                   s32 prev_cpu,
                   u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle)
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

    return cpu;
}

void BPF_STRUCT_OPS(fixed_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(fixed_tick, struct task_struct *p)
{
    set_target_cpuperf_if_local();
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fixed_init)
{
    set_target_cpuperf_unlocked();
    return 0;
}

void BPF_STRUCT_OPS(fixed_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(fixed_cpuperf_ops,
    .select_cpu = (void *)fixed_select_cpu,
    .enqueue    = (void *)fixed_enqueue,
    .tick       = (void *)fixed_tick,
    .init       = (void *)fixed_init,
    .exit       = (void *)fixed_exit,
    .name       = "fixed_cpuperf");