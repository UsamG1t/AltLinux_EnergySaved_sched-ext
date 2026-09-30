#!/usr/bin/env python3
"""Plot every run of an experiment series made by launch/experiments/run_series.py.

Per run (next to its logs):
  execution.png  plot_scx.py --main --power with the static schedule
  battery.png    plot_battery.py for battery.csv
Per series (in the series directory, matplotlib only):
  battery_consumed_<variant>.png  battery energy used since run start, all runs
  battery_consumed_all.png        the same for every run, coloured by variant
  energy_summary.png              RAPL and battery energy per run, grouped by variant
Without matplotlib the per-run graphs are written as .svg and the series
graphs are skipped.
"""

import argparse
import csv
import math
import statistics
import subprocess
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent
PLOT_SCX = RESULTS_DIR / "plot_scx.py"
PLOT_BATTERY = RESULTS_DIR / "plot_battery.py"
VARIANT_COLORS = {
    "borders": "#1d4ed8",
    "schedutil": "#c2410c",
    "powersave": "#0b6e4f",
}
FALLBACK_COLORS = ("#7c3aed", "#be123c", "#0369a1", "#a16207")
SUMMARY_METRICS = (
    ("pkg0_energy_j", "RAPL package, J"),
    ("pkg0_core_energy_j", "RAPL cores, J"),
    ("psys_energy_j", "RAPL platform (psys), J"),
    ("battery_used_j", "Battery used, J"),
)


def import_pyplot():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ModuleNotFoundError:
        return None
    return plt


def variant_color(variant: str, index: int) -> str:
    return VARIANT_COLORS.get(variant, FALLBACK_COLORS[index % len(FALLBACK_COLORS)])


def find_runs(series_dir: Path) -> list[Path]:
    return sorted(path.parent for path in series_dir.glob("*/run*/latest.csv"))


def run_plot(cmd: list[str]) -> bool:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip().splitlines()
        print(f"  failed: {' '.join(cmd[1:3])}...: {message[-1] if message else '?'}")
        return False
    return True


def plot_run(run_dir: Path, extension: str, skip_existing: bool) -> None:
    execution = run_dir / f"execution{extension}"
    if not (skip_existing and execution.exists()):
        cmd = [sys.executable, str(PLOT_SCX), "--main", "--power"]
        if (run_dir / "static_schedule.txt").is_file():
            cmd += ["--input", str(run_dir / "static_schedule.txt")]
        cmd += [str(run_dir / "latest.csv"), "-o", str(execution)]
        run_plot(cmd)

    battery = run_dir / f"battery{extension}"
    if (run_dir / "battery.csv").is_file() and not (skip_existing and battery.exists()):
        run_plot([sys.executable, str(PLOT_BATTERY), str(run_dir / "battery.csv"),
                  "-o", str(battery)])


def to_float(value: str | None) -> float:
    try:
        return float(value) if value not in (None, "", "None") else math.nan
    except ValueError:
        return math.nan


def battery_consumption(run_dir: Path) -> tuple[list[float], list[float]]:
    times: list[float] = []
    used_wh: list[float] = []
    start = None
    try:
        with (run_dir / "battery.csv").open(encoding="utf-8", newline="") as file:
            for row in csv.DictReader(file):
                elapsed = to_float(row.get("elapsed_sec"))
                energy = to_float(row.get("energy_now_uwh"))
                if not (math.isfinite(elapsed) and math.isfinite(energy)):
                    continue
                if start is None:
                    start = energy
                times.append(elapsed)
                used_wh.append((start - energy) / 1e6)
    except OSError:
        pass
    return times, used_wh


def plot_consumption(plt, runs: list[Path], output: Path, title: str) -> bool:
    fig, ax = plt.subplots(figsize=(11.5, 6.5))
    variants = sorted({run.parent.name for run in runs})
    drawn = False
    for run in runs:
        times, used = battery_consumption(run)
        if not times:
            continue
        drawn = True
        variant = run.parent.name
        ax.step(times, used, where="post", linewidth=1.8,
                color=variant_color(variant, variants.index(variant)),
                alpha=0.85, label=f"{variant}/{run.name}: {used[-1]:.3f} Wh")
    if not drawn:
        plt.close(fig)
        return False
    ax.set_title(title)
    ax.set_xlabel("Время (с)")
    ax.set_ylabel("Израсходовано энергии батареи (Вт·ч)")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(fontsize=8, ncol=2 if len(runs) > 8 else 1)
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return True


def read_summary(series_dir: Path) -> list[dict]:
    try:
        with (series_dir / "summary.csv").open(encoding="utf-8", newline="") as file:
            return list(csv.DictReader(file))
    except OSError:
        return []


def plot_energy_summary(plt, rows: list[dict], output: Path) -> bool:
    metrics = [(key, label) for key, label in SUMMARY_METRICS
               if any(math.isfinite(to_float(row.get(key))) for row in rows)]
    variants: list[str] = []
    for row in rows:
        if row["variant"] not in variants:
            variants.append(row["variant"])
    if not metrics or not variants:
        return False

    fig, axes = plt.subplots(1, len(metrics), figsize=(4.2 * len(metrics), 5.2),
                             squeeze=False)
    for ax, (key, label) in zip(axes[0], metrics):
        for index, variant in enumerate(variants):
            values = [to_float(row.get(key)) for row in rows
                      if row["variant"] == variant]
            values = [value for value in values if math.isfinite(value)]
            if not values:
                continue
            mean = statistics.fmean(values)
            spread = statistics.stdev(values) if len(values) > 1 else 0.0
            color = variant_color(variant, index)
            ax.bar(index, mean, yerr=spread, color=color, alpha=0.35,
                   capsize=6, edgecolor=color)
            ax.scatter([index] * len(values), values, color=color, zorder=3, s=18)
            ax.annotate(f"{mean:.1f}", (index, mean), textcoords="offset points",
                        xytext=(0, 6), ha="center", fontsize=9)
        ax.set_xticks(range(len(variants)), variants)
        ax.set_title(label)
        ax.grid(True, axis="y", linestyle="--", alpha=0.5)
    fig.suptitle("Energy per run: mean ± stdev, points = runs")
    fig.tight_layout()
    fig.savefig(output, dpi=150)
    plt.close(fig)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build all graphs of an experiment series (run_series.py output)"
    )
    parser.add_argument("series_dir", type=Path,
                        help="Series directory, e.g. results/experiments/<name>")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Do not rebuild per-run graphs that already exist")
    args = parser.parse_args()

    runs = find_runs(args.series_dir)
    if not runs:
        print(f"Error: no runs (*/run*/latest.csv) in {args.series_dir}", file=sys.stderr)
        return 1

    plt = import_pyplot()
    extension = ".png" if plt is not None else ".svg"
    for run in runs:
        print(f"{run.parent.name}/{run.name}")
        plot_run(run, extension, args.skip_existing)

    if plt is None:
        print("matplotlib is not installed: series graphs are skipped")
        return 0

    variants = sorted({run.parent.name for run in runs})
    for variant in variants:
        output = args.series_dir / f"battery_consumed_{variant}.png"
        if plot_consumption(plt, [run for run in runs if run.parent.name == variant],
                            output, f"Battery energy used: {variant}"):
            print(f"Graph saved to {output}")
    output = args.series_dir / "battery_consumed_all.png"
    if plot_consumption(plt, runs, output, "Battery energy used: all runs"):
        print(f"Graph saved to {output}")
    output = args.series_dir / "energy_summary.png"
    if plot_energy_summary(plt, read_summary(args.series_dir), output):
        print(f"Graph saved to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
