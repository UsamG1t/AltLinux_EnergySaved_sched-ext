#!/usr/bin/env python3

import argparse
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def parse_int_list(text: str) -> list[int]:
    values = []
    for part in text.split(","):
        part = part.strip().replace("_", "")
        if not part:
            continue
        values.append(int(part))
    if not values:
        raise argparse.ArgumentTypeError("empty target list")
    return values


def resolve_policy_dir(cpu: int) -> Path | None:
    cpu_cpufreq = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    if not cpu_cpufreq.exists():
        return None
    try:
        return cpu_cpufreq.resolve()
    except OSError:
        return None


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def clamp_freq(policy_dir: Path, freq_khz: int):
    min_path = policy_dir / "scaling_min_freq"
    max_path = policy_dir / "scaling_max_freq"

    old_min = read_text(min_path)
    old_max = read_text(max_path)

    write_text(min_path, str(freq_khz))
    write_text(max_path, str(freq_khz))

    return old_min, old_max


def restore_freq(policy_dir: Path, old_min: str, old_max: str) -> None:
    min_path = policy_dir / "scaling_min_freq"
    max_path = policy_dir / "scaling_max_freq"
    write_text(min_path, old_min)
    write_text(max_path, old_max)


def pin_cpu_preexec(cpu: int):
    def fn():
        os.sched_setaffinity(0, {cpu})
    return fn


def run_once(task_path: Path, cpu: int, runtime_ms: int, work_units_per_ms: int, rounds_per_unit: int) -> float:
    env = os.environ.copy()
    env["TASK_WORK_UNITS_PER_MS"] = str(work_units_per_ms)
    env["TASK_ROUNDS_PER_UNIT"] = str(rounds_per_unit)

    start_ns = time.monotonic_ns()
    proc = subprocess.run(
        [str(task_path), str(runtime_ms)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=pin_cpu_preexec(cpu),
    )
    end_ns = time.monotonic_ns()

    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"task exited with code {proc.returncode}")

    return (end_ns - start_ns) / 1_000_000.0


def median(values: list[float]) -> float:
    return statistics.median(values)


def main() -> int:
    ap = argparse.ArgumentParser(description="Calibrate TASK_WORK_UNITS_PER_MS for task_workload_origin")
    ap.add_argument("--workload", required=True, help="path to built task_workload_origin binary")
    ap.add_argument("--cpu", type=int, required=True, help="CPU to pin workload to")
    ap.add_argument("--current-work-units-per-ms", type=int, required=True, help="current TASK_WORK_UNITS_PER_MS")
    ap.add_argument("--rounds-per-unit", type=int, default=256, help="TASK_ROUNDS_PER_UNIT to keep fixed")
    ap.add_argument("--targets-ms", type=parse_int_list, default=[200, 500, 1000],
                    help="comma-separated calibration runtimes in ms, default: 200,500,1000")
    ap.add_argument("--runs", type=int, default=3, help="runs per target, default: 3")
    ap.add_argument("--freq-khz", type=int, default=0,
                    help="optional fixed frequency in kHz; if set, script clamps scaling_min/max to this value")
    args = ap.parse_args()

    workload = Path(args.workload).resolve()
    if not workload.exists():
        print(f"Error: workload not found: {workload}", file=sys.stderr)
        return 1

    policy_dir = resolve_policy_dir(args.cpu)
    old_limits = None

    if args.freq_khz:
        if policy_dir is None:
            print(f"Error: cpufreq policy for CPU{args.cpu} not found", file=sys.stderr)
            return 1
        try:
            old_limits = clamp_freq(policy_dir, args.freq_khz)
        except Exception as exc:
            print(f"Error: failed to clamp frequency on CPU{args.cpu}: {exc}", file=sys.stderr)
            print("Hint: run as root if you use --freq-khz", file=sys.stderr)
            return 1

    all_suggestions = []
    per_target = []

    try:
        with tempfile.TemporaryDirectory(prefix="task-calib-") as tmpdir:
            tmp_task = Path(tmpdir) / "task9999"
            tmp_task.symlink_to(workload)

            print(f"Calibrating on CPU{args.cpu}")
            if args.freq_khz:
                print(f"Fixed frequency: {args.freq_khz} kHz")
            else:
                print("Warning: frequency is not clamped by this script")
            print(f"Current TASK_WORK_UNITS_PER_MS: {args.current_work_units_per_ms}")
            print(f"Fixed TASK_ROUNDS_PER_UNIT:     {args.rounds_per_unit}")
            print()

            for target_ms in args.targets_ms:
                elapsed_samples = []
                suggestion_samples = []

                for run_idx in range(1, args.runs + 1):
                    elapsed_ms = run_once(
                        tmp_task,
                        args.cpu,
                        target_ms,
                        args.current_work_units_per_ms,
                        args.rounds_per_unit,
                    )
                    ratio = elapsed_ms / target_ms
                    suggested = round(args.current_work_units_per_ms * target_ms / elapsed_ms)

                    elapsed_samples.append(elapsed_ms)
                    suggestion_samples.append(suggested)
                    all_suggestions.append(suggested)

                    print(
                        f"target={target_ms:4d} ms "
                        f"run={run_idx}/{args.runs} "
                        f"elapsed={elapsed_ms:8.3f} ms "
                        f"ratio={ratio:6.3f} "
                        f"suggested={suggested}"
                    )

                med_elapsed = median(elapsed_samples)
                med_suggested = round(median(suggestion_samples))
                per_target.append((target_ms, med_elapsed, med_suggested))
                print(
                    f"  median for {target_ms:4d} ms: "
                    f"elapsed={med_elapsed:8.3f} ms "
                    f"suggested={med_suggested}"
                )
                print()

    finally:
        if old_limits and policy_dir is not None:
            try:
                restore_freq(policy_dir, old_limits[0], old_limits[1])
            except Exception as exc:
                print(f"Warning: failed to restore cpufreq limits: {exc}", file=sys.stderr)

    final_suggested = round(median(all_suggestions))

    print("=" * 72)
    print("Calibration summary")
    for target_ms, med_elapsed, med_suggested in per_target:
        print(
            f"  target={target_ms:4d} ms  "
            f"median_elapsed={med_elapsed:8.3f} ms  "
            f"median_suggested={med_suggested}"
        )

    print()
    print("Set these values:")
    print(f"  TASK_WORK_UNITS_PER_MS = {final_suggested}")
    print(f"  TASK_ROUNDS_PER_UNIT   = {args.rounds_per_unit}")
    print()
    print("If you want to patch source defaults:")
    print(f"  #define DEFAULT_WORK_UNITS_PER_MS {final_suggested}ULL")
    print(f"  #define DEFAULT_ROUNDS_PER_UNIT {args.rounds_per_unit}UL")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

