#!/usr/bin/env python3

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ISOLATED_CPUS = [6, 7, 8, 9]
MAX_FREQ_KHZ = 1_800_000
MIN_FREQ_KHZ = 400_000
ERF_SLACK_PCT = 0
FREQ_STEPS = [
    (1, 400_000, 48),
    (2, 600_000, 165),
    (3, 800_000, 256),
    (4, 900_000, 288),
    (5, 1_100_000, 352),
    (6, 1_300_000, 416),
    (7, 1_500_000, 480),
    (8, 1_600_000, 512),
    (9, 1_800_000, 576),
]
READY_MARKERS = (
    "Logging samples to",
    "Monitoring isolated CPUs",
    "Loaded ERF schedule",
)
@dataclass
class TaskInput:
    task_id: int
    runtime_ms: int
    ready_ms: int

    @property
    def name(self) -> str:
        return f"task{self.task_id}"


@dataclass
class TaskPlan:
    task_id: int
    runtime_ms: int
    ready_ms: int
    cpu: int
    freq_step_idx: int
    freq_khz: int
    perf_target: int
    order: int
    start_ns: int
    duration_ns: int

    @property
    def name(self) -> str:
        return f"task{self.task_id}"


class SimulatorError(Exception):
    pass


def ceil_div(num: int, den: int) -> int:
    return (num + den - 1) // den


def task_duration_ns(runtime_ms: int, freq_khz: int) -> int:
    return ceil_div(runtime_ms * MAX_FREQ_KHZ * 1_000_000, freq_khz)


def padded_slot_ns(runtime_ms: int) -> int:
    base_duration_ns = runtime_ms * 1_000_000
    if ERF_SLACK_PCT <= 0:
        return base_duration_ns
    return ceil_div(base_duration_ns * 100, 100 - ERF_SLACK_PCT)


def apply_schedule_slack(window_ns: int) -> int:
    if window_ns <= 0 or ERF_SLACK_PCT <= 0:
        return window_ns

    reserve_ns = ceil_div(window_ns * ERF_SLACK_PCT, 100)
    if reserve_ns >= window_ns:
        return 1

    return window_ns - reserve_ns


def parse_deadline_line(line: str) -> int | None:
    line = line.strip()
    if not line:
        return None
    if line[0].isdigit():
        if line.isdigit():
            return int(line)
        return None
    if line.startswith("deadline"):
        rest = line[len("deadline") :]
    elif line.startswith("D"):
        rest = line[1:]
    else:
        return None
    rest = rest.lstrip(":= \t")
    if not rest.isdigit():
        raise SimulatorError(f"Invalid deadline line: {line}")
    return int(rest)


def parse_task_token(token: str) -> TaskInput:
    if not token.startswith("task"):
        raise SimulatorError(f"Invalid task token: {token}")
    body = token[4:]
    if "@" not in body or "_" not in body:
        raise SimulatorError(f"Invalid task token: {token}")
    name_part, ready_s = body.split("@", 1)
    task_id_s, runtime_s = name_part.split("_", 1)
    if not task_id_s.isdigit() or not runtime_s.isdigit() or not ready_s.isdigit():
        raise SimulatorError(f"Invalid task token: {token}")
    return TaskInput(
        task_id=int(task_id_s),
        runtime_ms=int(runtime_s),
        ready_ms=int(ready_s),
    )


def parse_schedule_file(path: Path) -> tuple[int, list[TaskInput]]:
    deadline_ms: int | None = None
    tasks: list[TaskInput] = []

    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        maybe_deadline = parse_deadline_line(line)
        if maybe_deadline is not None:
            deadline_ms = maybe_deadline
            continue

        for token in line.replace(",", " ").replace(";", " ").split():
            tasks.append(parse_task_token(token))

    if deadline_ms is None or deadline_ms <= 0:
        raise SimulatorError(f"{path}: deadline is missing")
    if not tasks:
        raise SimulatorError(f"{path}: task set is empty")

    tasks.sort(key=lambda task: task.task_id)
    for idx, task in enumerate(tasks):
        if task.runtime_ms <= 0:
            raise SimulatorError(f"{path}: task{task.task_id} has zero runtime")
        if task.ready_ms >= deadline_ms:
            raise SimulatorError(
                f"{path}: task{task.task_id} ready time {task.ready_ms} is not earlier than deadline"
            )
        if task.ready_ms + task.runtime_ms > deadline_ms:
            raise SimulatorError(
                f"{path}: task{task.task_id} cannot finish by deadline even at max frequency"
            )
        if idx and tasks[idx - 1].task_id == task.task_id:
            raise SimulatorError(f"{path}: duplicate task id {task.task_id}")

    return deadline_ms, tasks


def choose_earliest_finish_cpu(
    cpu_states: list[dict[str, int]], task: TaskInput
) -> tuple[int, int, int]:
    ready_ns = task.ready_ms * 1_000_000
    base_duration_ns = padded_slot_ns(task.runtime_ms)
    best_idx = 0
    best_start_ns = 0
    best_end_ns = 0

    for idx, state in enumerate(cpu_states):
        start_ns = max(state["avail_ns"], ready_ns)
        end_ns = start_ns + base_duration_ns
        if idx == 0 or end_ns < best_end_ns:
            best_idx = idx
            best_start_ns = start_ns
            best_end_ns = end_ns
            continue
        if end_ns > best_end_ns:
            continue
        if state["load_ms"] < cpu_states[best_idx]["load_ms"]:
            best_idx = idx
            best_start_ns = start_ns
            best_end_ns = end_ns
            continue
        if (
            state["load_ms"] == cpu_states[best_idx]["load_ms"]
            and state["cpu"] < cpu_states[best_idx]["cpu"]
        ):
            best_idx = idx
            best_start_ns = start_ns
            best_end_ns = end_ns

    return best_idx, best_start_ns, best_end_ns


def find_step_for_required_khz(required_khz: int) -> tuple[int, int, int] | None:
    required_khz = max(required_khz, MIN_FREQ_KHZ)
    for step in FREQ_STEPS:
        if step[1] >= required_khz:
            return step
    return None


def choose_task_frequency(plan: TaskPlan, window_ns: int) -> None:
    required_khz = ceil_div(plan.runtime_ms * MAX_FREQ_KHZ * 1_000_000, window_ns)
    initial_step = find_step_for_required_khz(required_khz)
    if initial_step is None:
        raise SimulatorError(
            f"Task {plan.name} requires frequency above supported maximum"
        )

    for step_idx, freq_khz, perf_target in FREQ_STEPS[initial_step[0] - 1 :]:
        duration_ns = task_duration_ns(plan.runtime_ms, freq_khz)
        if duration_ns > window_ns:
            continue
        plan.freq_step_idx = step_idx
        plan.freq_khz = freq_khz
        plan.perf_target = perf_target
        plan.duration_ns = duration_ns
        return

    raise SimulatorError(f"Task {plan.name} cannot fit into its ERF window")


def build_erf_schedule(deadline_ms: int, tasks: list[TaskInput]) -> list[TaskPlan]:
    sorted_tasks = sorted(tasks, key=lambda task: (task.ready_ms, -task.runtime_ms, task.task_id))
    cpu_states: list[dict[str, int]] = [
        {
            "cpu": cpu,
            "load_ms": 0,
            "avail_ns": 0,
            "next_order": 0,
        }
        for cpu in ISOLATED_CPUS
    ]
    plans: list[TaskPlan] = []
    deadline_ns = deadline_ms * 1_000_000

    for task in sorted_tasks:
        cpu_idx, start_ns, end_ns = choose_earliest_finish_cpu(cpu_states, task)
        state = cpu_states[cpu_idx]
        if end_ns > deadline_ns:
            raise SimulatorError(
                f"ERF base assignment cannot finish {task.name} by deadline"
            )
        plans.append(
            TaskPlan(
                task_id=task.task_id,
                runtime_ms=task.runtime_ms,
                ready_ms=task.ready_ms,
                cpu=state["cpu"],
                freq_step_idx=0,
                freq_khz=0,
                perf_target=0,
                order=state["next_order"],
                start_ns=start_ns,
                duration_ns=0,
            )
        )
        state["next_order"] += 1
        state["load_ms"] += task.runtime_ms
        state["avail_ns"] = end_ns

    plans.sort(key=lambda plan: (plan.cpu, plan.order))

    for idx, plan in enumerate(plans):
        boundary_ns = deadline_ns
        if idx + 1 < len(plans) and plans[idx + 1].cpu == plan.cpu:
            boundary_ns = plans[idx + 1].start_ns
        if boundary_ns <= plan.start_ns:
            raise SimulatorError(f"Invalid ERF window for {plan.name}")
        choose_task_frequency(plan, apply_schedule_slack(boundary_ns - plan.start_ns))

    return plans


def print_schedule(deadline_ms: int, plans: Iterable[TaskPlan]) -> None:
    sorted_plans = sorted(plans, key=lambda plan: (plan.cpu, plan.order))
    print(f"Loaded ERF schedule for {len(sorted_plans)} tasks, deadline {deadline_ms:.3f} ms")
    print(f"Per-task slack reserve: {ERF_SLACK_PCT}% of each scheduling window")
    for idx, plan in enumerate(sorted_plans):
        if idx == 0 or sorted_plans[idx - 1].cpu != plan.cpu:
            print(f"CPU{plan.cpu}")
        print(
            f"  order={plan.order} {plan.name} runtime={plan.runtime_ms} "
            f"ready={float(plan.ready_ms):.3f}ms start={plan.start_ns / 1_000_000:.3f}ms "
            f"duration={plan.duration_ns / 1_000_000:.3f}ms "
            f"step={plan.freq_step_idx} freq={plan.freq_khz}"
        )


def parse_int_list(spec: str) -> list[int]:
    values: list[int] = []

    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if not part.isdigit():
            raise SimulatorError(f"Invalid integer list: {spec}")
        value = int(part)
        if value <= 0:
            raise SimulatorError(f"Calibration probe values must be positive: {spec}")
        values.append(value)

    if not values:
        raise SimulatorError("Calibration probe list is empty")

    return values


def find_step_by_index(step_idx: int) -> tuple[int, int, int]:
    for step in FREQ_STEPS:
        if step[0] == step_idx:
            return step
    raise SimulatorError(f"Unknown frequency step index: {step_idx}")


def read_int_file(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except FileNotFoundError as exc:
        raise SimulatorError(f"Missing sysfs file: {path}") from exc
    except PermissionError as exc:
        raise SimulatorError(f"Permission denied reading {path}") from exc
    except OSError as exc:
        raise SimulatorError(f"Failed to read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise SimulatorError(f"Invalid integer contents in {path}") from exc


def terminate_process_tree(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass


class SchedulerOutputWatcher:
    def __init__(self, proc: subprocess.Popen[bytes], log_path: Path):
        self.proc = proc
        self.log_path = log_path
        self.ready = threading.Event()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        with self.log_path.open("w", encoding="utf-8") as log:
            assert self.proc.stdout is not None
            for raw_line in self.proc.stdout:
                line = raw_line.decode("utf-8", errors="replace")
                sys.stdout.write(line)
                log.write(line)
                if any(marker in line for marker in READY_MARKERS):
                    self.ready.set()
        self.done.set()


def ensure_symlink(target: Path, link_path: Path) -> None:
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to(target)


def calibration_env_vars(args: argparse.Namespace, coeff: int) -> dict[str, str]:
    env = os.environ.copy()
    env["TASK_WORK_UNITS_PER_MS"] = str(coeff)
    env["TASK_ROUNDS_PER_UNIT"] = str(args.rounds_per_unit)
    env["TASK_VECTOR_LEN"] = str(args.rounds_per_unit)
    return env


def launch_simulation(args: argparse.Namespace, deadline_ms: int, plans: list[TaskPlan]) -> int:
    run_dir = args.run_dir.resolve()
    scheduler_bin = args.scheduler.resolve()
    origin_bin = args.origin.resolve()
    log_dir = run_dir / "logs"
    task_procs: list[subprocess.Popen[bytes]] = []
    task_links: list[Path] = []
    scheduler_proc: subprocess.Popen[bytes] | None = None

    if not scheduler_bin.is_file():
        raise SimulatorError(f"Scheduler binary not found: {scheduler_bin}")
    if not origin_bin.is_file():
        raise SimulatorError(f"Task origin binary not found: {origin_bin}")

    run_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    for plan in plans:
        link_path = run_dir / plan.name
        ensure_symlink(origin_bin, link_path)
        task_links.append(link_path)

    env = calibration_env_vars(args, args.work_units_per_ms)

    scheduler_cmd = [str(scheduler_bin), "-f", str(args.sample_interval), str(args.task_file)]
    print("Starting scheduler:", " ".join(scheduler_cmd))
    scheduler_proc = subprocess.Popen(
        scheduler_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )
    watcher = SchedulerOutputWatcher(scheduler_proc, log_dir / "scheduler.log")
    watcher.start()

    ready_timeout = time.monotonic() + args.ready_timeout
    while time.monotonic() < ready_timeout:
        if watcher.ready.is_set():
            break
        if scheduler_proc.poll() is not None:
            raise SimulatorError("Scheduler exited before becoming ready")
        time.sleep(0.05)
    else:
        raise SimulatorError("Timed out waiting for scheduler activation")

    start_monotonic = time.monotonic()
    release_plans = sorted(plans, key=lambda plan: (plan.start_ns, plan.cpu, plan.order))

    try:
        for plan in release_plans:
            target_time = start_monotonic + plan.start_ns / 1_000_000_000.0
            while True:
                now = time.monotonic()
                remaining = target_time - now
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.01))

            task_path = run_dir / plan.name
            print(
                f"[+{plan.start_ns / 1_000_000:.3f} ms] launch {plan.name} "
                f"cpu={plan.cpu} step={plan.freq_step_idx} freq={plan.freq_khz}"
            )
            proc = subprocess.Popen(
                [str(task_path), str(plan.runtime_ms)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
            task_procs.append(proc)

        failed = False
        for proc, plan in zip(task_procs, release_plans):
            rc = proc.wait()
            if rc != 0:
                failed = True
                stderr_data = b""
                if proc.stderr is not None:
                    stderr_data = proc.stderr.read()
                sys.stderr.write(
                    f"{plan.name} exited with rc={rc}\n{stderr_data.decode('utf-8', errors='replace')}"
                )

        if scheduler_proc.poll() is None:
            terminate_process_tree(scheduler_proc)

        return 1 if failed else 0
    finally:
        for proc in task_procs:
            terminate_process_tree(proc)
        terminate_process_tree(scheduler_proc)
        for link_path in task_links:
            try:
                link_path.unlink()
            except FileNotFoundError:
                pass


def run_requested_actions(args: argparse.Namespace, origin_bin: Path) -> int:
    if args.task_file is None:
        raise SimulatorError("task_file is required")

    deadline_ms, tasks = parse_schedule_file(args.task_file)
    plans = build_erf_schedule(deadline_ms, tasks)
    print_schedule(deadline_ms, plans)
    if args.dry_run:
        return 0
    return launch_simulation(args, deadline_ms, plans)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ERF-R-DVFS based load simulator for scx_erf"
    )
    parser.add_argument(
        "task_file",
        nargs="?",
        type=Path,
        help="Input workload file with tokens taskN_runtime@ready",
    )
    parser.add_argument(
        "--scheduler",
        type=Path,
        default=Path("./build/scx_erf/scx_erf"),
        help="Path to scx_erf binary",
    )
    parser.add_argument(
        "--origin",
        type=Path,
        default=Path("./build/common/task_workload_origin"),
        help="Path to origin CPU-bound task binary",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path("./build/scx_erf/run"),
        help="Directory for symlinks and logs",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=0.1,
        help="Sampling interval passed to scx_erf",
    )
    parser.add_argument(
        "--work-units-per-ms",
        type=int,
        default=233,
        help="Work coefficient exported to tasks as TASK_WORK_UNITS_PER_MS",
    )
    parser.add_argument(
        "--rounds-per-unit",
        type=int,
        default=256,
        help="Inner arithmetic rounds per work unit exported as TASK_ROUNDS_PER_UNIT",
    )
    parser.add_argument(
        "--vector-len",
        type=int,
        dest="rounds_per_unit",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--ready-timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for scheduler activation",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only solve and print the schedule, do not launch anything",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        if args.rounds_per_unit <= 0:
            raise SimulatorError("--rounds-per-unit must be positive")

        origin_bin = args.origin.resolve()
        if not origin_bin.is_file():
            raise SimulatorError(f"Task origin binary not found: {origin_bin}")
        return run_requested_actions(args, origin_bin)
    except SimulatorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
