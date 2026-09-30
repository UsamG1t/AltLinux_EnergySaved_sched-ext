# AltLinux_EnergySaved_sched-ext

Based on https://github.com/sched-ext/scx, C/eBPF schedulers with frequency management.

## Repository layout

- `scheds/scx_stairs` — `scx_stairs` scheduler sources.
- `scheds/scx_erf` — `scx_erf` scheduler sources.
- `scheds/scx_scheduler` — `scx_scheduler` scheduler sources.
- `scheds/scx_borders` — `scx_borders` scheduler sources.
- `launch/common` — shared launch assets and common task workload source.
- `launch/scx_stairs` — `scx_stairs` launch helpers.
- `launch/scx_erf` — `scx_erf` simulator.
- `launch/scx_scheduler` — `scx_scheduler` simulator.
- `launch/scx_borders` — `scx_borders` simulator.
- `build` — generated binaries, BPF objects, skeletons and temporary run directories.
- `results` — experiment outputs and plotting tools.

## Main build targets

```bash
make scx_stairs
make scx_erf
make scx_scheduler
make scx_borders
make fixed_cpuperf
make task_workload_origin
```

The build products are written to `build/<name>`.

`scx_borders` is a separate scheduler with its own simulator and static
schedule format. Its schedule stores frequency values directly and does not use
`perf_target`; task frequencies are applied from user space by updating
`scaling_min_freq` and `scaling_max_freq`.

```bash
python3 launch/scx_borders/scx_borders_sim.py \
  launch/common/test_schedule.txt
```

Use `--max-frequency` to assign the maximum configured frequency to every
generated task. Use `--loop` to repeat the schedule indefinitely; in this mode
`deadline_ms` is also the period:

```bash
python3 launch/scx_borders/scx_borders_sim.py \
  --loop --max-frequency \
  launch/common/test_schedule.txt
```

Loop mode also works with `--static-schedule`. `results/scx_borders/latest.csv`
contains elapsed time and `cycle_index`; `latest.csv` and `dbg.log` are flushed
and synchronized to disk once per second.

`scx_borders` also records battery measurements separately in
`results/scx_borders/battery.csv`. The file contains elapsed time, cycle index,
remaining energy, instantaneous power, voltage, charge percentage, battery
status and AC connection state. Missing power-supply fields are written as
`None`; battery monitoring never changes the format of `latest.csv`.

Plot one or more battery logs on the same graph:

```bash
python3 results/plot_battery.py \
  results/experiment-a/battery.csv \
  results/experiment-b/battery.csv
```

Each line is labelled with the input file name without its extension.

Use `--union` to restrict all series to their common energy range and align
them at the same time and energy origin. Use `--log` to display time on a
logarithmic scale; the flags can be combined:

```bash
python3 results/plot_battery.py --union --log \
  results/experiment-a/battery.csv \
  results/experiment-b/battery.csv
```

## `scx_scheduler`: calibration and run cycle

The `scx_scheduler` pipeline has two mandatory calibration stages before the
first real run on a new machine:

1. calibrate the workload coefficient for `task_workload_origin`;
2. calibrate the `perf_target` ladder for the target isolated CPUs and the
   target frequency domain.

The steps below describe the full cycle from calibration to log analysis.

### 1. Build the required binaries

Build the scheduler, the fixed-frequency helper and the workload binary:

```bash
make scx_scheduler fixed_cpuperf task_workload_origin
```

### 2. Choose isolated CPUs and patch the source defaults

`scx_scheduler` must use the same isolated CPUs in the Python launcher and in
the C/eBPF scheduler sources.

Update these files before calibration:

- `launch/scx_scheduler/scx_scheduler_sim.py`
  - `ISOLATED_CPUS`
- `scheds/scx_scheduler/scx_scheduler.c`
  - `ISOLATED_START`
  - `ISOLATED_END`
- `scheds/scx_scheduler/scx_scheduler.bpf.c`
  - `ISOLATED_START`
  - `ISOLATED_END`

Important:

- `scx_scheduler_sim.py` accepts an explicit list of CPUs;
- the C and eBPF parts currently expect a contiguous CPU range from
  `ISOLATED_START` to `ISOLATED_END`.

Example for CPUs `0` and `1`:

```python
# launch/scx_scheduler/scx_scheduler_sim.py
ISOLATED_CPUS = [0, 1]
```

```c
/* scheds/scx_scheduler/scx_scheduler.c */
#define ISOLATED_START 0
#define ISOLATED_END 1
```

```c
/* scheds/scx_scheduler/scx_scheduler.bpf.c */
#define ISOLATED_START 0
#define ISOLATED_END 1
```

Rebuild after editing the isolated CPU configuration:

```bash
make scx_scheduler fixed_cpuperf task_workload_origin
```

### 3. Calibrate `task_workload_origin`

Run `launch/common/calibrate_task.py` on one of the isolated CPUs. The script
launches the workload pinned to the selected CPU, compares the measured runtime
with the requested runtime and prints the corrected defaults.

Required parameters:

- `--workload`
- `--cpu`
- `--current-work-units-per-ms`

Recommended parameters:

- `--rounds-per-unit`
- `--freq-khz`

Example:

```bash
sudo python3 launch/common/calibrate_task.py \
  --workload build/common/task_workload_origin \
  --cpu 0 \
  --current-work-units-per-ms 521 \
  --rounds-per-unit 256 \
  --freq-khz 1700000
```

After the script finishes, copy the printed values into:

- `launch/common/task_workload_origin.c`
  - `DEFAULT_WORK_UNITS_PER_MS`
  - `DEFAULT_ROUNDS_PER_UNIT`
- `launch/scx_scheduler/scx_scheduler_sim.py`
  - default value of `--work-units-per-ms`
  - default value of `--rounds-per-unit`

Rebuild the workload and the scheduler after changing the defaults:

```bash
make scx_scheduler task_workload_origin
```

### 4. Calibrate the `perf_target` ladder

Run `launch/common/calibrate_freq_ladder.py` on one of the isolated CPUs. The
script iterates over `perf_target` values, applies them through
`fixed_cpuperf`, launches a pinned workload on the same CPU and measures the
actual frequency using `scaling_cur_freq` and `cpuinfo_avg_freq`.

Required parameter:

- `--cpu`

Recommended parameters:

- `--workload`
- `--fixed-cpuperf`
- `--task-work-units-per-ms`
- `--task-rounds-per-unit`

Example for the usual `cpupower`-based mode:

```bash
sudo python3 launch/common/calibrate_freq_ladder.py \
  --cpu 0 \
  --fixed-cpuperf build/fixed_cpuperf/fixed_cpuperf \
  --workload build/common/task_workload_origin \
  --task-work-units-per-ms 521 \
  --task-rounds-per-unit 256
```

If the machine runs with `intel_pstate=passive` and `cpupower` does not expose
the frequency steps, use the scheduler ladder as the source of candidate
frequencies:

```bash
sudo python3 launch/common/calibrate_freq_ladder.py \
  --cpu 0 \
  --passive-scheduler \
  --fixed-cpuperf build/fixed_cpuperf/fixed_cpuperf \
  --workload build/common/task_workload_origin \
  --task-work-units-per-ms 521 \
  --task-rounds-per-unit 256
```

After the script finishes, copy the printed values into:

- `launch/scx_scheduler/scx_scheduler_sim.py`
  - `MAX_FREQ_KHZ`
  - `MIN_FREQ_KHZ`
  - `FREQ_STEPS`

Rebuild after changing the ladder:

```bash
make scx_scheduler fixed_cpuperf
```

### 5. Prepare the input file

`scx_scheduler_sim.py` supports two input modes:

- a task description file, from which the script builds a static schedule;
- a ready-made static schedule file.

#### 5.1. Task description file

The task file must contain a deadline and a list of tasks in the form
`taskN_runtime@ready`.

Example:

```text
deadline=35000

task1_12000@0
task2_4000@1000
task3_3000@13000
task4_6000@16000
task5_3000@22000
task6_7000@25000
```

#### 5.2. Ready-made static schedule

If a schedule has already been prepared, it can be passed directly with
`--static-schedule`. In that mode, the launcher sends the file to the
scheduler and releases tasks according to the same schedule.

### 6. Run a dry run

Always start with a dry run. It verifies the task file or the static schedule,
prints the computed schedule and does not launch the real scheduler.

Task file mode:

```bash
python3 launch/scx_scheduler/scx_scheduler_sim.py \
  launch/common/test_schedule.txt \
  --dry-run
```

Static schedule mode:

```bash
python3 launch/scx_scheduler/scx_scheduler_sim.py \
  --static-schedule build/scx_scheduler/run/static_schedule.txt \
  --dry-run
```

### 7. Run the full experiment

Task file mode:

```bash
python3 launch/scx_scheduler/scx_scheduler_sim.py \
  launch/common/test_schedule.txt
```

Static schedule mode:

```bash
python3 launch/scx_scheduler/scx_scheduler_sim.py \
  --static-schedule build/scx_scheduler/run/static_schedule.txt
```

The main output files are:

- `build/scx_scheduler/run/static_schedule.txt`
- `results/scx_scheduler/latest.csv`
- `results/scx_scheduler/dbg.log`

Notes:

- `results/scx_scheduler/latest.csv` contains frequency samples and scheduler
  debug counters;
- `results/scx_scheduler/dbg.log` contains the detailed debug stream;
- if `time_in_state` is unavailable on the machine, the `cpu*_policy_mhz`
  fields are written as `None`, while the run continues using
  `scaling_cur_freq` and `cpuinfo_avg_freq`.

#### RAPL energy and power

`scx_scheduler` and `scx_borders` also sample the RAPL energy counters from
`/sys/class/powercap/intel-rapl:*` on every sampling interval. RAPL domains are
machine-wide (package, all cores together, uncore, DRAM, platform), not
per-CPU.

- `latest.csv` gets two columns per domain after the per-CPU columns:
  `rapl_<domain>_energy_j` (energy since the start of the run, counter
  wrap-around handled) and `rapl_<domain>_power_w` (average power over the
  last sampling interval);
- domain names come from the powercap zone names: `pkg0` (`package-0`),
  `pkg0_core`, `pkg0_uncore`, `pkg0_dram`, `psys`;
- `dbg.log` gets a `rapl:` line after each `dbg:` line;
- the scheduler prints the found domains at start and the energy and average
  power per domain at exit.

`energy_uj` is readable by root only. The schedulers are started as root, so
no extra setup is needed. If RAPL is missing or unreadable, the run continues
with a warning and the RAPL fields are written as `None`.

### 8. Plot the main run results

Plot the normal run metrics with the static schedule shown on the first row:

```bash
python3 results/plot_scx.py \
  --main \
  --input build/scx_scheduler/run/static_schedule.txt \
  results/scx_scheduler/latest.csv
```

To limit the graph to a subset of CPUs, use `-c` with a list or a range:

```bash
python3 results/plot_scx.py \
  -c 0-1 \
  --main \
  --input build/scx_scheduler/run/static_schedule.txt \
  results/scx_scheduler/latest.csv
```

Add `--power` to append two full-width rows under the per-CPU rows: RAPL
instantaneous power (W) and cumulative energy (J) for every RAPL domain. The
energy legend shows the energy consumed inside the displayed time range:

```bash
python3 results/plot_scx.py \
  --main \
  --power \
  --input build/scx_scheduler/run/static_schedule.txt \
  results/scx_scheduler/latest.csv
```

Use `-o` to save the graph to a file instead of opening a window, for example
on a machine reached over ssh. With matplotlib the format follows the
extension (`.png`, `.svg`, `.pdf`); without matplotlib only `.svg` is
supported:

```bash
python3 results/plot_scx.py \
  --main \
  --power \
  --input build/scx_borders/run/static_schedule.txt \
  results/scx_borders/latest.csv \
  -o results/scx_borders/latest.png
```

`--borders` selects `results/scx_borders/latest.csv` as the default log, like
`--scheduler` and `--erf` do for their schedulers.

### 9. Plot the debug log

Plot the classified scheduler debug timeline:

```bash
python3 results/dbg_plot.py results/scx_scheduler/dbg.log
```

This graph is useful for checking:

- whether the planned task was running on the intended CPU;
- whether another task preempted it;
- whether the requested frequency and the observed frequency diverged;
- whether the CPU spent time in idle state.

### 10. Recommended iteration loop

For a new machine, the practical loop is:

1. patch isolated CPU definitions;
2. rebuild;
3. run `calibrate_task.py`;
4. copy the printed task defaults into the source files;
5. rebuild;
6. run `calibrate_freq_ladder.py`;
7. copy the printed ladder into `scx_scheduler_sim.py`;
8. rebuild;
9. prepare a task file or a static schedule;
10. run a dry run;
11. run the full experiment;
12. inspect `latest.csv`, `dbg.log`, the main graphs and the debug graphs;
13. if the CPU set or the frequency domain changes, repeat the calibration.
