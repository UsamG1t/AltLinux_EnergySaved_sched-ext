#!/usr/bin/env python3
"""Run a series of comparison experiments: scx_borders vs kernel cpufreq governors.

Every run uses the same workload launcher (launch/scx_borders/scx_borders_sim.py)
and the same measurement code (scx_borders sampling loop), so only the
frequency/scheduling policy differs between variants:

  borders    intel_pstate=active,  governor powersave, scx_borders loaded
  schedutil  intel_pstate=passive, governor schedutil, monitor-only, tasks pinned
  powersave  intel_pstate=active,  governor powersave, monitor-only, tasks pinned

Runs are interleaved (borders, schedutil, powersave, borders, ...). The original
intel_pstate mode, governors, EPP and frequency limits are restored at the end,
also on Ctrl-C. Must be started as root from the repository root.
"""

import argparse
import csv
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

CPU_SYSFS = Path("/sys/devices/system/cpu")
CPUFREQ_SYSFS = CPU_SYSFS / "cpufreq"
PSTATE_SYSFS = CPU_SYSFS / "intel_pstate"
POWER_SUPPLY_SYSFS = Path("/sys/class/power_supply")
SCHED_EXT_STATE = Path("/sys/kernel/sched_ext/state")
ISOLATED_CPUS = (0, 1)
SIM_PATH = Path("launch/scx_borders/scx_borders_sim.py")
BORDERS_BIN = Path("build/scx_borders/scx_borders")
ORIGIN_BIN = Path("build/common/task_workload_origin")


@dataclass(frozen=True)
class Variant:
    name: str
    pstate: str
    governor: str
    baseline: bool


VARIANTS = {
    "borders": Variant("borders", "active", "powersave", baseline=False),
    "schedutil": Variant("schedutil", "passive", "schedutil", baseline=True),
    "powersave": Variant("powersave", "active", "powersave", baseline=True),
}


class SeriesError(Exception):
    pass


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def write_text(path: Path, value: str) -> None:
    try:
        path.write_text(value + "\n", encoding="utf-8")
    except OSError as exc:
        raise SeriesError(f"cannot write '{value}' to {path}: {exc}") from exc


def policy_dirs() -> list[Path]:
    return sorted(CPUFREQ_SYSFS.glob("policy[0-9]*"),
                  key=lambda path: int(path.name[len("policy"):]))


def find_power_supply(kind: str) -> Path | None:
    for supply in sorted(POWER_SUPPLY_SYSFS.glob("*")):
        if read_text(supply / "type") == kind:
            return supply
    return None


def power_snapshot() -> dict:
    battery = find_power_supply("Battery")
    mains = find_power_supply("Mains")
    snapshot: dict = {"ac_online": read_text(mains / "online") if mains else None}
    if battery:
        for field in ("status", "capacity", "energy_now", "energy_full",
                      "power_now", "voltage_now"):
            snapshot[f"battery_{field}"] = read_text(battery / field)
    return snapshot


def thermal_snapshot() -> dict:
    temps = {}
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        kind = read_text(zone / "type")
        temp = read_text(zone / "temp")
        if kind and temp and temp.lstrip("-").isdigit():
            temps[f"{zone.name}:{kind}"] = int(temp) / 1000.0
    return temps


def cpufreq_snapshot() -> dict:
    policies = {}
    for policy in policy_dirs():
        policies[policy.name] = {
            "governor": read_text(policy / "scaling_governor"),
            "driver": read_text(policy / "scaling_driver"),
            "epp": read_text(policy / "energy_performance_preference"),
            "min_khz": read_text(policy / "scaling_min_freq"),
            "max_khz": read_text(policy / "scaling_max_freq"),
        }
    return {
        "intel_pstate_status": read_text(PSTATE_SYSFS / "status"),
        "no_turbo": read_text(PSTATE_SYSFS / "no_turbo"),
        "policies": policies,
    }


def environment_facts() -> dict:
    cpu_model = None
    for line in (read_text(Path("/proc/cpuinfo")) or "").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    siblings = {
        cpu: read_text(CPU_SYSFS / f"cpu{cpu}/topology/thread_siblings_list")
        for cpu in ISOLATED_CPUS
    }
    commit = subprocess.run(
        ["git", "-c", "safe.directory=*", "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or None
    return {
        "kernel": platform.release(),
        "cpu_model": cpu_model,
        "cmdline": read_text(Path("/proc/cmdline")),
        "cpus_online": read_text(CPU_SYSFS / "online"),
        "smt_control": read_text(CPU_SYSFS / "smt/control"),
        "isolated_cpu_siblings": siblings,
        "cpu_core_cpus": read_text(Path("/sys/devices/cpu_core/cpus")),
        "git_commit": commit,
    }


def set_freq_limits(policy: Path, min_khz: str, max_khz: str) -> None:
    current_max = int(read_text(policy / "scaling_max_freq") or "0")
    if int(min_khz) > current_max:
        write_text(policy / "scaling_max_freq", max_khz)
        write_text(policy / "scaling_min_freq", min_khz)
    else:
        write_text(policy / "scaling_min_freq", min_khz)
        write_text(policy / "scaling_max_freq", max_khz)


def set_pstate_status(status: str) -> None:
    if read_text(PSTATE_SYSFS / "status") != status:
        write_text(PSTATE_SYSFS / "status", status)
        time.sleep(0.5)
    if read_text(PSTATE_SYSFS / "status") != status:
        raise SeriesError(f"intel_pstate did not switch to {status}")


def apply_variant(variant: Variant, saved: dict) -> None:
    set_pstate_status(variant.pstate)
    for policy in policy_dirs():
        available = (read_text(policy / "scaling_available_governors") or "").split()
        if variant.governor not in available:
            raise SeriesError(
                f"{policy.name}: governor {variant.governor} is not available "
                f"in intel_pstate={variant.pstate} (available: {' '.join(available)})"
            )
        write_text(policy / "scaling_governor", variant.governor)
        # A mode switch may reset EPP; pin it to the series-start value so
        # every active-mode run sees the same preference.
        epp = saved["policies"].get(policy.name, {}).get("epp")
        if variant.pstate == "active" and epp and (
                policy / "energy_performance_preference").exists():
            write_text(policy / "energy_performance_preference", epp)


def restore_cpufreq(saved: dict) -> list[str]:
    errors = []
    try:
        set_pstate_status(saved["intel_pstate_status"])
    except SeriesError as exc:
        errors.append(str(exc))
    for policy in policy_dirs():
        state = saved["policies"].get(policy.name)
        if not state:
            continue
        try:
            if state["governor"]:
                write_text(policy / "scaling_governor", state["governor"])
            if state["epp"] and (policy / "energy_performance_preference").exists():
                write_text(policy / "energy_performance_preference", state["epp"])
            if state["min_khz"] and state["max_khz"]:
                set_freq_limits(policy, state["min_khz"], state["max_khz"])
        except SeriesError as exc:
            errors.append(str(exc))
    return errors


def preflight(args: argparse.Namespace) -> list[str]:
    """Return warnings; raise SeriesError for conditions that block the series."""
    warnings = []
    if os.geteuid() != 0:
        raise SeriesError("run as root: the series switches intel_pstate and governors")
    for path in (SIM_PATH, BORDERS_BIN, ORIGIN_BIN, args.task_file):
        if not path.is_file():
            raise SeriesError(f"{path} not found (start from the repository root, build first)")
    state = read_text(SCHED_EXT_STATE)
    if state != "disabled":
        raise SeriesError(f"sched_ext state is '{state}', another scheduler is loaded")
    if read_text(PSTATE_SYSFS / "status") is None:
        raise SeriesError("intel_pstate is not in use, variants cannot be switched")
    for cpu in ISOLATED_CPUS:
        if cpu and read_text(CPU_SYSFS / f"cpu{cpu}/online") == "0":
            raise SeriesError(f"CPU{cpu} is offline")
        siblings = read_text(CPU_SYSFS / f"cpu{cpu}/topology/thread_siblings_list")
        if siblings != str(cpu):
            message = f"CPU{cpu} shares its core with CPUs {siblings} (SMT is on)"
            if not args.allow_smt:
                raise SeriesError(message + "; use --allow-smt to run anyway")
            warnings.append(message)
    core_cpus = read_text(Path("/sys/devices/cpu_core/cpus"))
    if core_cpus is not None:
        warnings.append(f"P-core CPUs (cpu_core): {core_cpus}")
    power = power_snapshot()
    if power.get("ac_online") == "1":
        if not args.allow_ac:
            raise SeriesError("AC adapter is online; unplug it or use --allow-ac")
        warnings.append("AC adapter is online: battery data will not show consumption")
    if not power.get("battery_energy_now"):
        warnings.append("battery energy_now is unavailable: battery plots will be empty")
    return warnings


def last_csv_row(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8", newline="") as file:
            row = None
            for row in csv.DictReader(file):
                pass
            return row
    except OSError:
        return None


def to_float(value: str | None) -> float:
    try:
        return float(value) if value not in (None, "", "None") else math.nan
    except ValueError:
        return math.nan


def summarize_run(run_dir: Path) -> dict:
    summary: dict = {}
    latest = last_csv_row(run_dir / "latest.csv")
    if latest:
        summary["monitored_sec"] = to_float(latest.get("elapsed_sec"))
        for key, value in latest.items():
            if key.startswith("rapl_") and key.endswith("_energy_j"):
                summary[key[len("rapl_"):]] = to_float(value)
    try:
        with (run_dir / "latest.csv").open(encoding="utf-8", newline="") as file:
            sums = {cpu: [0.0, 0] for cpu in ISOLATED_CPUS}
            for row in csv.DictReader(file):
                for cpu in ISOLATED_CPUS:
                    value = to_float(row.get(f"cpu{cpu}_avg_mhz"))
                    if math.isfinite(value):
                        sums[cpu][0] += value
                        sums[cpu][1] += 1
            for cpu, (total, count) in sums.items():
                summary[f"cpu{cpu}_mean_avg_mhz"] = total / count if count else math.nan
    except OSError:
        pass
    energy = []
    capacity = []
    try:
        with (run_dir / "battery.csv").open(encoding="utf-8", newline="") as file:
            for row in csv.DictReader(file):
                value = to_float(row.get("energy_now_uwh"))
                if math.isfinite(value):
                    energy.append(value)
                value = to_float(row.get("capacity_pct"))
                if math.isfinite(value):
                    capacity.append(value)
    except OSError:
        pass
    if energy:
        summary["battery_start_wh"] = energy[0] / 1e6
        summary["battery_end_wh"] = energy[-1] / 1e6
        summary["battery_used_j"] = (energy[0] - energy[-1]) / 1e6 * 3600.0
    if capacity:
        summary["capacity_start_pct"] = capacity[0]
        summary["capacity_end_pct"] = capacity[-1]
    counts = {"released": 0, "done": 0, "missed": 0, "killed": 0, "failed": 0}
    try:
        with (run_dir / "tasks.csv").open(encoding="utf-8", newline="") as file:
            for row in csv.DictReader(file):
                counts["released"] += 1
                counts[row["status"]] = counts.get(row["status"], 0) + 1
                if row["status"] == "done" and row["met_deadline"] == "0":
                    counts["missed"] += 1
    except (OSError, KeyError):
        pass
    summary.update({f"tasks_{key}": value for key, value in counts.items()})
    return summary


def write_summary_csv(path: Path, rows: list[dict]) -> None:
    keys: list[str] = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: (f"{value:.6f}" if isinstance(value, float) else value)
                for key, value in row.items()
            })


def run_one(args: argparse.Namespace, variant: Variant, repeat: int,
            run_dir: Path) -> int:
    cmd = [
        sys.executable, str(SIM_PATH), str(args.task_file),
        "--loop",
        "--duration", str(args.duration),
        "--sample-interval", str(args.sample_interval),
        "--run-dir", str(Path("build/experiments/run").resolve()),
        "--results-dir", str(run_dir),
    ]
    if variant.baseline:
        cmd.append("--baseline")
    print(f"  $ {' '.join(cmd)}", flush=True)
    with (run_dir / "sim.log").open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            return proc.wait(timeout=args.duration + args.ready_timeout + 60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
            return 124
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)


def chown_tree(path: Path, owner: str) -> None:
    subprocess.run(["chown", "-R", owner, str(path)], check=False)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interleaved experiment series: scx_borders vs schedutil vs powersave"
    )
    parser.add_argument("--task-file", type=Path,
                        default=Path("launch/common/test_schedule.txt"),
                        help="Task set, repeated with --loop (default: %(default)s)")
    parser.add_argument("--variants", default="borders,schedutil,powersave",
                        help="Comma-separated variants in run order (default: %(default)s)")
    parser.add_argument("--repeats", type=int, default=5,
                        help="Runs per variant (default: %(default)s)")
    parser.add_argument("--duration", type=float, default=300.0,
                        help="Seconds per run (default: %(default)s)")
    parser.add_argument("--cooldown", type=float, default=60.0,
                        help="Idle seconds between runs (default: %(default)s)")
    parser.add_argument("--settle", type=float, default=5.0,
                        help="Idle seconds after switching a variant (default: %(default)s)")
    parser.add_argument("--sample-interval", type=float, default=0.1,
                        help="scx_borders sampling interval, s (default: %(default)s)")
    parser.add_argument("--ready-timeout", type=float, default=10.0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--output-root", type=Path, default=Path("results/experiments"),
                        help="Where series directories are created (default: %(default)s)")
    parser.add_argument("--name", default=time.strftime("%Y%m%d-%H%M%S"),
                        help="Series directory name (default: current time)")
    parser.add_argument("--owner",
                        help="chown the series directory to this user[:group] at the end")
    parser.add_argument("--allow-ac", action="store_true",
                        help="Run even when the AC adapter is online")
    parser.add_argument("--allow-smt", action="store_true",
                        help="Run even when CPU0/CPU1 share a core with other CPUs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only run the checks and print the plan; change nothing")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    try:
        variants = [VARIANTS[name] for name in args.variants.split(",") if name]
    except KeyError as exc:
        print(f"Error: unknown variant {exc}; known: {', '.join(VARIANTS)}", file=sys.stderr)
        return 1
    if not variants or args.repeats < 1 or args.duration <= 0 or args.cooldown < 0:
        print("Error: need at least one variant, --repeats >= 1, --duration > 0, "
              "--cooldown >= 0", file=sys.stderr)
        return 1

    order = [(repeat, variant) for repeat in range(1, args.repeats + 1)
             for variant in variants]
    total_sec = len(order) * (args.duration + args.settle) + (len(order) - 1) * args.cooldown
    series_dir = args.output_root / args.name

    try:
        warnings = preflight(args)
    except SeriesError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"Note: {warning}")
    print(f"Series {series_dir}: {len(order)} runs x {args.duration:.0f} s, "
          f"cooldown {args.cooldown:.0f} s, about {total_sec / 60:.1f} min")
    for index, (repeat, variant) in enumerate(order, 1):
        print(f"  {index:2d}. {variant.name:9s} run{repeat:02d}  "
              f"intel_pstate={variant.pstate} governor={variant.governor} "
              f"{'monitor-only, pinned tasks' if variant.baseline else 'scx_borders'}")
    if args.dry_run:
        return 0
    if series_dir.exists():
        print(f"Error: {series_dir} already exists", file=sys.stderr)
        return 1

    saved = cpufreq_snapshot()
    series_dir.mkdir(parents=True)
    manifest = {
        "args": {key: str(value) for key, value in vars(args).items()},
        "variants": {variant.name: vars(variant) for variant in variants},
        "order": [f"{variant.name}/run{repeat:02d}" for repeat, variant in order],
        "environment": environment_facts(),
        "initial_cpufreq": saved,
        "initial_power": power_snapshot(),
        "warnings": warnings,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "runs": [],
    }
    manifest_path = series_dir / "manifest.json"
    rows: list[dict] = []
    exit_code = 0

    def save_manifest() -> None:
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                 encoding="utf-8")

    def on_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_sigterm)
    save_manifest()
    try:
        for index, (repeat, variant) in enumerate(order, 1):
            run_dir = series_dir / variant.name / f"run{repeat:02d}"
            run_dir.mkdir(parents=True)
            print(f"[{index}/{len(order)}] {variant.name} run{repeat:02d} "
                  f"({time.strftime('%H:%M:%S')})", flush=True)
            apply_variant(variant, saved)
            time.sleep(args.settle)
            info = {
                "variant": vars(variant), "repeat": repeat, "order": index,
                "start": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "before": {"cpufreq": cpufreq_snapshot(), "power": power_snapshot(),
                           "thermal": thermal_snapshot()},
            }
            rc = run_one(args, variant, repeat, run_dir)
            info.update({
                "end": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "returncode": rc,
                "after": {"cpufreq": cpufreq_snapshot(), "power": power_snapshot(),
                          "thermal": thermal_snapshot()},
            })
            (run_dir / "run_info.json").write_text(
                json.dumps(info, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            row = {"variant": variant.name, "repeat": repeat, "order": index,
                   "returncode": rc}
            row.update(summarize_run(run_dir))
            rows.append(row)
            write_summary_csv(series_dir / "summary.csv", rows)
            manifest["runs"].append({"dir": str(run_dir.relative_to(series_dir)),
                                     "returncode": rc})
            save_manifest()
            print(f"  rc={rc} pkg0={row.get('pkg0_energy_j', math.nan):.1f} J "
                  f"battery_used={row.get('battery_used_j', math.nan):.1f} J "
                  f"tasks done={row['tasks_done']} missed={row['tasks_missed']} "
                  f"killed={row['tasks_killed']}", flush=True)
            if rc != 0:
                exit_code = 1
            if index < len(order):
                time.sleep(args.cooldown)
    except KeyboardInterrupt:
        print("Interrupted, restoring cpufreq state", file=sys.stderr)
        exit_code = 130
    except SeriesError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        errors = restore_cpufreq(saved)
        manifest["restored_cpufreq"] = cpufreq_snapshot()
        manifest["restore_errors"] = errors
        manifest["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save_manifest()
        for error in errors:
            print(f"Warning: restore: {error}", file=sys.stderr)
        if args.owner:
            chown_tree(series_dir, args.owner)
    print(f"Series results: {series_dir}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
