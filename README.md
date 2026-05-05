# AltLinux_EnergySaved_sched-ext

Based on https://github.com/sched-ext/scx, C/eBPF schedulers with frequency management.

## Repository layout

- `scheds/scx_stairs` — `scx_stairs` scheduler sources.
- `scheds/scx_erf` — `scx_erf` scheduler sources.
- `scheds/scx_scheduler` — `scx_scheduler` scheduler sources.
- `launch/common` — shared launch assets and common task workload source.
- `launch/scx_stairs` — `scx_stairs` launch helpers.
- `launch/scx_erf` — `scx_erf` simulator.
- `launch/scx_scheduler` — `scx_scheduler` simulator.
- `build` — generated binaries, BPF objects, skeletons and temporary run directories.
- `results` — experiment outputs and plotting tools.

## Main build targets

```bash
make scx_stairs
make scx_erf
make scx_scheduler
make task_workload_origin
```

The build products are written to `build/<name>`.
