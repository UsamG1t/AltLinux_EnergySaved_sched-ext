#!/usr/bin/env python3

import argparse
import ast
import math
import os
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCX_CPUPERF_ONE = 1024
DEFAULT_SCHEDULER_SIM = (
    Path(__file__).resolve().parents[1] / "scx_scheduler" / "scx_scheduler_sim.py"
)


def parse_freq_token(text: str) -> int:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(GHz|MHz|kHz)", text)
    if not match:
        raise ValueError(f"cannot parse frequency token: {text!r}")

    value = float(match.group(1))
    unit = match.group(2)

    if unit == "GHz":
        return round(value * 1_000_000)
    if unit == "MHz":
        return round(value * 1_000)
    if unit == "kHz":
        return round(value)

    raise ValueError(f"unsupported unit: {unit}")


def parse_cpupower_steps(cpu: int) -> list[int]:
    proc = subprocess.run(
        ["cpupower", "--cpu", str(cpu), "frequency-info"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)

    steps = []
    for line in proc.stdout.splitlines():
        if "available frequency steps:" not in line:
            continue
        _, rhs = line.split(":", 1)
        parts = [part.strip() for part in rhs.split(",") if part.strip()]
        for part in parts:
            steps.append(parse_freq_token(part))
        break

    if not steps:
        raise RuntimeError("could not parse 'available frequency steps' from cpupower")

    return sorted(set(steps))


def parse_scheduler_steps(sim_path: Path) -> list[int]:
    try:
        source = sim_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"failed to read {sim_path}: {exc}") from exc

    try:
        tree = ast.parse(source, filename=str(sim_path))
    except SyntaxError as exc:
        raise RuntimeError(f"failed to parse {sim_path}: {exc}") from exc

    freq_steps_value = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "FREQ_STEPS":
                freq_steps_value = ast.literal_eval(node.value)
                break
        if freq_steps_value is not None:
            break

    if freq_steps_value is None:
        raise RuntimeError(f"FREQ_STEPS not found in {sim_path}")

    steps = []
    for idx, item in enumerate(freq_steps_value, start=1):
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            raise RuntimeError(
                f"invalid FREQ_STEPS entry #{idx} in {sim_path}: {item!r}"
            )
        freq_khz = item[1]
        if not isinstance(freq_khz, int):
            raise RuntimeError(
                f"invalid frequency in FREQ_STEPS entry #{idx} in {sim_path}: {item!r}"
            )
        steps.append(freq_khz)

    if not steps:
        raise RuntimeError(f"no frequencies found in FREQ_STEPS in {sim_path}")

    return sorted(set(steps))


def read_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def resolve_policy_dir(cpu: int) -> Path:
    path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    if not path.exists():
        raise RuntimeError(f"cpufreq directory for CPU{cpu} not found")
    return path.resolve()


def pin_cpu_preexec(cpu: int):
    def fn():
        os.sched_setaffinity(0, {cpu})

    return fn


def khz_for_exact_perf(perf: int, cpuinfo_max_khz: int) -> int:
    khz = math.ceil(perf * cpuinfo_max_khz / SCX_CPUPERF_ONE)
    while (khz * SCX_CPUPERF_ONE) // cpuinfo_max_khz < perf:
        khz += 1
    while khz > 1 and ((khz - 1) * SCX_CPUPERF_ONE) // cpuinfo_max_khz >= perf:
        khz -= 1
    return khz


def start_fixed_cpuperf(
    fixed_cpuperf: Path, cpu: int, perf: int, cpuinfo_max_khz: int
) -> subprocess.Popen:
    target_khz = khz_for_exact_perf(perf, cpuinfo_max_khz)

    proc = subprocess.Popen(
        [str(fixed_cpuperf), str(cpu), str(target_khz)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    time.sleep(0.5)

    if proc.poll() is not None:
        err = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(
            f"fixed_cpuperf exited early for perf={perf}, target_khz={target_khz}\n{err}"
        )

    return proc


def stop_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_workload_and_sample(
    task_path: Path,
    cpu: int,
    runtime_ms: int,
    policy_dir: Path,
    work_units_per_ms: int,
    rounds_per_unit: int,
    sample_interval: float,
) -> dict:
    env = os.environ.copy()
    env["TASK_WORK_UNITS_PER_MS"] = str(work_units_per_ms)
    env["TASK_ROUNDS_PER_UNIT"] = str(rounds_per_unit)

    proc = subprocess.Popen(
        [str(task_path), str(runtime_ms)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        preexec_fn=pin_cpu_preexec(cpu),
    )

    scaling_samples = []
    avg_samples = []

    while proc.poll() is None:
        scaling = read_int(policy_dir / "scaling_cur_freq")
        avg = read_int(policy_dir / "cpuinfo_avg_freq")

        if scaling is not None and scaling > 0:
            scaling_samples.append(scaling)
        if avg is not None and avg > 0:
            avg_samples.append(avg)

        time.sleep(sample_interval)

    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode != 0:
        raise RuntimeError(stderr.strip() or f"workload exited with code {proc.returncode}")

    if avg_samples:
        measured_khz = round(statistics.median(avg_samples))
        source = "cpuinfo_avg_freq"
    elif scaling_samples:
        measured_khz = round(statistics.median(scaling_samples))
        source = "scaling_cur_freq"
    else:
        raise RuntimeError("no cpufreq samples collected during workload")

    return {
        "measured_khz": measured_khz,
        "scaling_khz": round(statistics.median(scaling_samples))
        if scaling_samples
        else None,
        "avg_khz": round(statistics.median(avg_samples)) if avg_samples else None,
        "source": source,
    }


def closest_step(freq_khz: int, available_steps: list[int]) -> tuple[int, int]:
    best = min(available_steps, key=lambda step: abs(step - freq_khz))
    return best, abs(best - freq_khz)


def choose_nine(items: list[dict]) -> list[dict]:
    if len(items) <= 9:
        return items[:]

    chosen = []
    last_idx = len(items) - 1
    for i in range(9):
        idx = round(i * last_idx / 8)
        chosen.append(items[idx])
    return chosen


def fmt_khz(value: int | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:_d}"


def load_available_steps(args: argparse.Namespace) -> tuple[list[int], str]:
    if args.passive_scheduler:
        sim_path = args.scheduler_sim.resolve()
        return parse_scheduler_steps(sim_path), f"FREQ_STEPS in {sim_path}"
    return parse_cpupower_steps(args.cpu), f"cpupower --cpu {args.cpu} frequency-info"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Scan SCX perf values and match them to available cpufreq steps"
    )
    ap.add_argument("--cpu", type=int, required=True, help="CPU to test")
    ap.add_argument(
        "--fixed-cpuperf",
        default="build/fixed_cpuperf/fixed_cpuperf",
        help="path to fixed_cpuperf binary",
    )
    ap.add_argument(
        "--workload",
        default="build/common/task_workload_origin",
        help="path to task_workload_origin binary",
    )
    ap.add_argument(
        "--runtime-ms", type=int, default=400, help="workload duration per perf value"
    )
    ap.add_argument(
        "--sample-interval",
        type=float,
        default=0.03,
        help="cpufreq sample interval in seconds",
    )
    ap.add_argument("--perf-min", type=int, default=1)
    ap.add_argument("--perf-max", type=int, default=1024)
    ap.add_argument("--perf-step", type=int, default=1)
    ap.add_argument(
        "--tolerance-khz",
        type=int,
        default=60_000,
        help="max deviation from available step",
    )
    ap.add_argument("--task-work-units-per-ms", type=int, default=886)
    ap.add_argument("--task-rounds-per-unit", type=int, default=256)
    ap.add_argument(
        "--passive-scheduler",
        action="store_true",
        help=(
            "take available frequency steps from launch/scx_scheduler/"
            "scx_scheduler_sim.py:FREQ_STEPS instead of cpupower"
        ),
    )
    ap.add_argument(
        "--scheduler-sim",
        type=Path,
        default=DEFAULT_SCHEDULER_SIM,
        help=(
            "path to scx_scheduler_sim.py used with --passive-scheduler "
            f"(default: {DEFAULT_SCHEDULER_SIM})"
        ),
    )
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Run as root.", file=sys.stderr)
        return 1

    fixed_cpuperf = Path(args.fixed_cpuperf).resolve()
    workload = Path(args.workload).resolve()

    if not fixed_cpuperf.exists():
        print(f"fixed_cpuperf not found: {fixed_cpuperf}", file=sys.stderr)
        return 1
    if not workload.exists():
        print(f"workload not found: {workload}", file=sys.stderr)
        return 1

    policy_dir = resolve_policy_dir(args.cpu)
    cpuinfo_max_khz = read_int(policy_dir / "cpuinfo_max_freq")
    if not cpuinfo_max_khz:
        print("Could not read cpuinfo_max_freq", file=sys.stderr)
        return 1

    try:
        available, source = load_available_steps(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"CPU{args.cpu} available target steps from {source}:")
    print(" ", available)
    print()

    best_for_step = {}

    with tempfile.TemporaryDirectory(prefix="perfscan-") as tmpdir:
        tmp_task = Path(tmpdir) / "task9999"
        tmp_task.symlink_to(workload)

        for perf in range(args.perf_min, args.perf_max + 1, args.perf_step):
            fixed_proc = None
            try:
                fixed_proc = start_fixed_cpuperf(
                    fixed_cpuperf, args.cpu, perf, cpuinfo_max_khz
                )

                sample = run_workload_and_sample(
                    tmp_task,
                    args.cpu,
                    args.runtime_ms,
                    policy_dir,
                    args.task_work_units_per_ms,
                    args.task_rounds_per_unit,
                    args.sample_interval,
                )

                measured_khz = sample["measured_khz"]
                step_khz, err_khz = closest_step(measured_khz, available)

                print(
                    f"perf={perf:4d}  "
                    f"measured={measured_khz:8d}  "
                    f"closest_step={step_khz:8d}  "
                    f"err={err_khz:6d}  "
                    f"scaling={fmt_khz(sample['scaling_khz']):>8}  "
                    f"avg={fmt_khz(sample['avg_khz']):>8}  "
                    f"src={sample['source']}"
                )

                if err_khz <= args.tolerance_khz:
                    candidate = {
                        "step_khz": step_khz,
                        "perf": perf,
                        "measured_khz": measured_khz,
                        "err_khz": err_khz,
                        "source": sample["source"],
                        "scaling_khz": sample["scaling_khz"],
                        "avg_khz": sample["avg_khz"],
                    }
                    prev = best_for_step.get(step_khz)
                    if prev is None or candidate["err_khz"] < prev["err_khz"]:
                        best_for_step[step_khz] = candidate

            finally:
                if fixed_proc is not None:
                    stop_proc(fixed_proc)

    matched = [best_for_step[key] for key in sorted(best_for_step)]
    print()
    print(f"Matched available steps: {len(matched)} / {len(available)}")
    for item in matched:
        print(
            f"  step={item['step_khz']:_d}  "
            f"perf={item['perf']:4d}  "
            f"measured={item['measured_khz']:_d}  "
            f"err={item['err_khz']:_d}"
        )

    print()
    if len(matched) < 9:
        print("WARNING: fewer than 9 matched steps found.")
        print("Increase runtime, reduce tolerance strictness, or inspect the full scan.")
        return 0

    chosen = choose_nine(matched)

    print("Suggested 9-step ladder:")
    print(f"MAX_FREQ_KHZ = {chosen[-1]['step_khz']:_d}")
    print(f"MIN_FREQ_KHZ = {chosen[0]['step_khz']:_d}")
    print("ERF_SLACK_PCT = 0")
    print("FREQ_STEPS = [")
    for idx, item in enumerate(chosen, start=1):
        print(
            f"    ({idx}, {item['step_khz']:_d}, {item['perf']}),"
            f"  # measured {item['measured_khz']:_d}, err {item['err_khz']:_d}"
        )
    print("]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

