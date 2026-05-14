/* fixed_cpuperf.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include "fixed_cpuperf.bpf.skel.h"

#ifndef SCX_CPUPERF_ONE
#define SCX_CPUPERF_ONE 1024U
#endif

static volatile sig_atomic_t exit_req;

static void sig_handler(int sig)
{
    exit_req = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct fixed_cpuperf *skel;
    struct bpf_link *link;
    int cpu = 2;
    unsigned int perf = SCX_CPUPERF_ONE;
    unsigned long target_khz = 0;
    unsigned long max_khz = 0;
    char path[256];
    FILE *f;

    if (argc >= 2)
        cpu = atoi(argv[1]);

    /*
     * Optional second argument:
     *   ./fixed_cpuperf 2 1800000
     *
     * Convert target kHz to SCX relative performance:
     *   perf = target_khz / cpuinfo_max_freq * SCX_CPUPERF_ONE
     */
    if (argc >= 3) {
        target_khz = strtoul(argv[2], NULL, 10);

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq",
                 cpu);

        f = fopen(path, "r");
        if (!f) {
            fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
            return 1;
        }

        if (fscanf(f, "%lu", &max_khz) != 1 || max_khz == 0) {
            fprintf(stderr, "failed to read cpuinfo_max_freq\n");
            fclose(f);
            return 1;
        }

        fclose(f);

        perf = target_khz * SCX_CPUPERF_ONE / max_khz;

        if (perf > SCX_CPUPERF_ONE)
            perf = SCX_CPUPERF_ONE;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = SCX_OPS_OPEN(fixed_cpuperf_ops, fixed_cpuperf);
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->target_cpu = cpu;
    skel->rodata->target_perf = perf;

    SCX_OPS_LOAD(skel, fixed_cpuperf_ops, fixed_cpuperf, uei);

    link = SCX_OPS_ATTACH(skel, fixed_cpuperf_ops, fixed_cpuperf);
    if (!link) {
        fprintf(stderr, "failed to attach sched_ext scheduler\n");
        fixed_cpuperf__destroy(skel);
        return 1;
    }

    printf("attached fixed_cpuperf: cpu=%d perf=%u / %u\n",
           cpu, perf, SCX_CPUPERF_ONE);
    printf("check: cat /sys/kernel/sched_ext/state\n");
    printf("check: cat /sys/kernel/sched_ext/root/ops\n");

    while (!exit_req && !UEI_EXITED(skel, uei))
        sleep(1);

    bpf_link__destroy(link);
    UEI_REPORT(skel, uei);
    fixed_cpuperf__destroy(skel);

    printf("detached fixed_cpuperf\n");
    return 0;
}
