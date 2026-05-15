import argparse
import csv
import math
import re
import sys
from html import escape
from pathlib import Path


DEFAULT_STAIRS_LOG_PATH = Path("./results/scx_stairs/latest.csv")
DEFAULT_SCHEDULER_LOG_PATH = Path("./results/scx_scheduler/latest.csv")
DEFAULT_ERF_LOG_PATH = Path("./results/scx_erf/latest.csv")
CPU_METRIC_RE = re.compile(r"^cpu(\d+)_(policy|scaling|avg)_mhz$")
CPU_OLD_RE = re.compile(r"^cpu(\d+)_mhz$")

METRIC_ORDER = ("policy", "scaling", "avg")
METRIC_LABELS = {
    "policy": "policy_step(time_in_state)",
    "scaling": "scaling_cur_freq",
    "avg": "cpuinfo_avg_freq",
}
METRIC_COLORS = {
    "policy": "#1d4ed8",
    "scaling": "#0b6e4f",
    "avg": "#c2410c",
}
METRIC_DASHES = {
    "policy": None,
    "scaling": "8 4",
    "avg": "2 3",
}
METRIC_LINESTYLES = {
    "policy": "-",
    "scaling": "--",
    "avg": ":",
}
METRIC_WIDTHS = {
    "policy": 2.2,
    "scaling": 2.0,
    "avg": 2.0,
}


def parse_time_range(spec: str) -> tuple[float, float]:
    parts = spec.split("-", 1)
    if len(parts) != 2:
        raise ValueError("time range must look like <start>-<end>")

    start = float(parts[0])
    end = float(parts[1])
    if start < 0 or end < 0:
        raise ValueError("time range must be non-negative")
    if end < start:
        raise ValueError("time range end must be >= start")

    return start, end


def metric_field(cpu: int, metric: str) -> str:
    return f"cpu{cpu}_{metric}_mhz"


def load_log_rows(path: Path) -> tuple[list[int], tuple[str, ...], list[dict[str, float]]]:
    rows: list[dict[str, float]] = []

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError("log file has no header")
        if "elapsed_sec" not in reader.fieldnames:
            raise ValueError("log file is missing elapsed_sec column")

        columns: dict[int, dict[str, str]] = {}
        for field in reader.fieldnames:
            match = CPU_METRIC_RE.match(field)
            if match:
                cpu = int(match.group(1))
                metric = match.group(2)
                columns.setdefault(cpu, {})[metric] = field
                continue

            match = CPU_OLD_RE.match(field)
            if match:
                cpu = int(match.group(1))
                columns.setdefault(cpu, {})["scaling"] = field

        if not columns:
            raise ValueError("log file has no CPU frequency columns")

        cpus = sorted(columns)
        metrics = tuple(
            metric for metric in METRIC_ORDER
            if any(metric in columns[cpu] for cpu in cpus)
        )

        for raw_row in reader:
            row = {"elapsed_sec": float(raw_row["elapsed_sec"])}
            for cpu in cpus:
                for metric in metrics:
                    field = columns[cpu].get(metric)
                    key = metric_field(cpu, metric)
                    if field is None:
                        row[key] = math.nan
                        continue

                    value = raw_row.get(field, "")
                    row[key] = float(value)
            rows.append(row)

    return cpus, metrics, rows


def select_metrics(available_metrics: tuple[str, ...], debug: bool) -> tuple[str, ...]:
    if debug:
        return available_metrics

    if "policy" in available_metrics:
        return ("policy",)
    if "scaling" in available_metrics:
        return ("scaling",)
    if "avg" in available_metrics:
        return ("avg",)

    return available_metrics


def filter_rows(rows: list[dict[str, float]],
                time_range: tuple[float, float] | None) -> list[dict[str, float]]:
    if time_range is None:
        return rows

    start, end = time_range
    return [row for row in rows if start <= row["elapsed_sec"] <= end]


def finite_values(rows: list[dict[str, float]], cpus: list[int],
                  metrics: tuple[str, ...]) -> list[float]:
    values = []

    for row in rows:
        for cpu in cpus:
            for metric in metrics:
                value = row[metric_field(cpu, metric)]
                if math.isfinite(value):
                    values.append(value)

    return values


def y_limits(values: list[float]) -> tuple[float, float]:
    low = min(values)
    high = max(values)

    if math.isclose(low, high):
        pad = max(low * 0.05, 50.0)
    else:
        pad = max((high - low) * 0.05, 50.0)

    return max(0.0, low - pad), high + pad


def cpu_metric_series(rows: list[dict[str, float]], cpu: int,
                      metric: str) -> tuple[list[float], list[float]]:
    times = []
    freqs = []

    for row in rows:
        value = row[metric_field(cpu, metric)]
        if not math.isfinite(value):
            continue
        times.append(row["elapsed_sec"])
        freqs.append(value)

    return times, freqs


def import_pyplot():
    try:
        import matplotlib.pyplot as plt
    except ModuleNotFoundError:
        return None

    return plt


def svg_output_path(log_path: Path, single_cpu: int | None) -> Path:
    suffix = f"_cpu{single_cpu}" if single_cpu is not None else ""
    return log_path.with_name(f"{log_path.stem}{suffix}.svg")


def write_svg(output_path: Path, contents: str) -> Path:
    try:
        output_path.write_text(contents, encoding="utf-8")
        return output_path
    except PermissionError:
        fallback_path = Path.cwd() / output_path.name
        fallback_path.write_text(contents, encoding="utf-8")
        return fallback_path


def axis_ticks(low: float, high: float, count: int = 5) -> list[float]:
    if count < 2:
        return [low, high]
    step = (high - low) / (count - 1)
    return [low + step * index for index in range(count)]


def step_points(times: list[float], freqs: list[float]) -> list[tuple[float, float]]:
    points = []
    if not times:
        return points

    points.append((times[0], freqs[0]))
    for index in range(1, len(times)):
        points.append((times[index], freqs[index - 1]))
        points.append((times[index], freqs[index]))

    return points


def map_x(value: float, x0: float, x1: float, width: float) -> float:
    if math.isclose(x0, x1):
        return width / 2.0
    return (value - x0) * width / (x1 - x0)


def map_y(value: float, y0: float, y1: float, height: float) -> float:
    if math.isclose(y0, y1):
        return height / 2.0
    return height - (value - y0) * height / (y1 - y0)


def render_svg_legend(parts: list[str], metrics: tuple[str, ...],
                      origin_x: float, origin_y: float) -> None:
    x = origin_x

    for metric in metrics:
        color = METRIC_COLORS[metric]
        label = METRIC_LABELS[metric]
        parts.append(
            f'<line x1="{x:.1f}" y1="{origin_y:.1f}" x2="{x + 18:.1f}" y2="{origin_y:.1f}" '
            f'stroke="{color}" stroke-width="3"/>'
        )
        parts.append(
            f'<text x="{x + 24:.1f}" y="{origin_y + 4:.1f}" font-family="sans-serif" '
            f'font-size="11">{escape(label)}</text>'
        )
        x += 120.0


def render_svg_panel(parts: list[str], rows: list[dict[str, float]], cpu: int,
                     metrics: tuple[str, ...], limits: tuple[float, float],
                     x_limits: tuple[float, float], origin_x: float,
                     origin_y: float, width: float, height: float) -> None:
    inner_left = 62.0
    inner_right = 18.0
    inner_top = 44.0
    inner_bottom = 42.0
    plot_x = origin_x + inner_left
    plot_y = origin_y + inner_top
    plot_width = width - inner_left - inner_right
    plot_height = height - inner_top - inner_bottom
    y_ticks = axis_ticks(limits[0], limits[1])
    x_ticks = axis_ticks(x_limits[0], x_limits[1])
    has_data = False

    parts.append(
        f'<rect x="{origin_x:.1f}" y="{origin_y:.1f}" width="{width:.1f}" height="{height:.1f}" '
        'fill="#ffffff" stroke="#d7dde5" stroke-width="1"/>'
    )
    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(f"CPU {cpu}")}</text>'
    )
    render_svg_legend(parts, metrics, origin_x + 18.0, origin_y + 32.0)

    for tick in y_ticks:
        y = plot_y + map_y(tick, limits[0], limits[1], plot_height)
        parts.append(
            f'<line x1="{plot_x:.1f}" y1="{y:.1f}" x2="{plot_x + plot_width:.1f}" y2="{y:.1f}" '
            'stroke="#e5eaef" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{plot_x - 8:.1f}" y="{y + 4:.1f}" font-family="sans-serif" '
            f'font-size="11" text-anchor="end">{tick:.0f}</text>'
        )

    for tick in x_ticks:
        x = plot_x + map_x(tick, x_limits[0], x_limits[1], plot_width)
        parts.append(
            f'<line x1="{x:.1f}" y1="{plot_y:.1f}" x2="{x:.1f}" y2="{plot_y + plot_height:.1f}" '
            'stroke="#f0f3f6" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{plot_y + plot_height + 18:.1f}" font-family="sans-serif" '
            f'font-size="11" text-anchor="middle">{tick:.1f}</text>'
        )

    parts.append(
        f'<rect x="{plot_x:.1f}" y="{plot_y:.1f}" width="{plot_width:.1f}" height="{plot_height:.1f}" '
        'fill="none" stroke="#94a3b8" stroke-width="1"/>'
    )

    for metric in metrics:
        times, freqs = cpu_metric_series(rows, cpu, metric)
        if not times:
            continue

        has_data = True
        points = step_points(times, freqs)
        svg_points = " ".join(
            f"{plot_x + map_x(time, x_limits[0], x_limits[1], plot_width):.1f},"
            f"{plot_y + map_y(freq, limits[0], limits[1], plot_height):.1f}"
            for time, freq in points
        )
        parts.append(
            f'<polyline fill="none" stroke="{METRIC_COLORS[metric]}" '
            f'stroke-width="{METRIC_WIDTHS[metric]:.1f}" '
            + (f'stroke-dasharray="{METRIC_DASHES[metric]}" ' if METRIC_DASHES[metric] else "")
            + f'points="{svg_points}"/>'
        )

    if not has_data:
        parts.append(
            f'<text x="{plot_x + plot_width / 2:.1f}" y="{plot_y + plot_height / 2:.1f}" '
            'font-family="sans-serif" font-size="13" text-anchor="middle" fill="#64748b">'
            'No data</text>'
        )

    parts.append(
        f'<text x="{plot_x + plot_width / 2:.1f}" y="{origin_y + height - 8:.1f}" '
        'font-family="sans-serif" font-size="12" text-anchor="middle">Time (s)</text>'
    )
    parts.append(
        f'<text x="{origin_x + 16:.1f}" y="{plot_y + plot_height / 2:.1f}" '
        'font-family="sans-serif" font-size="12" text-anchor="middle" '
        f'transform="rotate(-90 {origin_x + 16:.1f} {plot_y + plot_height / 2:.1f})">'
        'Frequency (MHz)</text>'
    )


def render_svg(rows: list[dict[str, float]], cpus: list[int],
               metrics: tuple[str, ...],
               time_range: tuple[float, float] | None, single_cpu: int | None,
               output_path: Path, source_name: str) -> Path:
    display_cpus = [single_cpu] if single_cpu is not None else cpus
    values = finite_values(rows, display_cpus, metrics)
    if not values:
        raise ValueError("no finite frequency samples in the selected range")

    limits = y_limits(values)
    x_limits = (
        time_range
        if time_range is not None
        else (rows[0]["elapsed_sec"], rows[-1]["elapsed_sec"])
    )

    title = (
        f"{source_name} frequency history for CPU {single_cpu}"
        if single_cpu is not None
        else f"{source_name} frequency history for isolated CPUs"
    )
    if time_range is not None:
        title += f" ({time_range[0]:g}-{time_range[1]:g} s)"

    if single_cpu is not None:
        width = 1100.0
        height = 440.0
        panels = [(display_cpus[0], 40.0, 70.0, width - 80.0, height - 110.0)]
    else:
        width = 1200.0
        height = 860.0
        panels = []
        panel_width = 540.0
        panel_height = 320.0
        for index, cpu in enumerate(display_cpus):
            row = index // 2
            col = index % 2
            panels.append((
                cpu,
                40.0 + col * (panel_width + 40.0),
                70.0 + row * (panel_height + 40.0),
                panel_width,
                panel_height,
            ))

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        f'<text x="{width / 2:.1f}" y="34" font-family="sans-serif" font-size="20" '
        f'font-weight="bold" text-anchor="middle">{escape(title)}</text>',
    ]

    for cpu, origin_x, origin_y, panel_width, panel_height in panels:
        render_svg_panel(
            parts,
            rows,
            cpu,
            metrics,
            limits,
            x_limits,
            origin_x,
            origin_y,
            panel_width,
            panel_height,
        )

    parts.append("</svg>")
    return write_svg(output_path, "\n".join(parts))


def plot_cpu(ax, rows: list[dict[str, float]], cpu: int,
             metrics: tuple[str, ...], limits: tuple[float, float]) -> None:
    has_data = False

    for metric in metrics:
        times, freqs = cpu_metric_series(rows, cpu, metric)
        if not times:
            continue

        has_data = True
        ax.step(
            times,
            freqs,
            where="post",
            linewidth=METRIC_WIDTHS[metric],
            linestyle=METRIC_LINESTYLES[metric],
            color=METRIC_COLORS[metric],
            label=METRIC_LABELS[metric],
        )

    if not has_data:
        ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                ha="center", va="center")
    else:
        ax.legend(loc="upper right", fontsize=9)

    ax.set_title(f"CPU {cpu}")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frequency (MHz)")
    ax.set_ylim(*limits)
    ax.grid(True, linestyle="--", alpha=0.5)


def plot_rows(rows: list[dict[str, float]], cpus: list[int],
              metrics: tuple[str, ...],
              time_range: tuple[float, float] | None, single_cpu: int | None,
              log_path: Path, source_name: str) -> None:
    plt = import_pyplot()
    if plt is None:
        output_path = render_svg(rows, cpus, metrics, time_range, single_cpu,
                                 svg_output_path(log_path, single_cpu),
                                 source_name)
        print(f"matplotlib is not installed, SVG graph saved to {output_path}")
        return

    display_cpus = [single_cpu] if single_cpu is not None else cpus
    values = finite_values(rows, display_cpus, metrics)
    if not values:
        raise ValueError("no finite frequency samples in the selected range")

    limits = y_limits(values)
    x_limits = (
        time_range
        if time_range is not None
        else (rows[0]["elapsed_sec"], rows[-1]["elapsed_sec"])
    )

    if single_cpu is not None:
        fig, ax = plt.subplots(figsize=(12, 5))
        plot_cpu(ax, rows, single_cpu, metrics, limits)
        ax.set_xlim(*x_limits)
        title = f"{source_name} frequency history for CPU {single_cpu}"
    else:
        fig, axes = plt.subplots(2, 2, figsize=(14, 8), sharex=True)
        for ax, cpu in zip(axes.flat, cpus):
            plot_cpu(ax, rows, cpu, metrics, limits)
            ax.set_xlim(*x_limits)
        title = f"{source_name} frequency history for isolated CPUs"

    if time_range is not None:
        start, end = time_range
        title += f" ({start:g}-{end:g} s)"

    fig.suptitle(title)
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.96))
    plt.show()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plot frequency logs collected by scx_stairs, scx_scheduler, or scx_erf."
    )
    parser.add_argument(
        "file_path",
        nargs="?",
        help="Path to the CSV log file; if omitted, the default source log is used",
    )
    parser.add_argument(
        "-t",
        dest="time_range",
        metavar="N-M",
        help="Show only the time range from N to M seconds",
    )
    parser.add_argument(
        "-c",
        dest="cpu",
        type=int,
        help="Show only one isolated CPU instead of the default four plots",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show all available lines instead of only the main policy line",
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--scheduler",
        action="store_true",
        help=f"Use scx_scheduler log by default ({DEFAULT_SCHEDULER_LOG_PATH}) instead of scx_stairs",
    )
    source_group.add_argument(
        "--erf",
        action="store_true",
        help=f"Use scx_erf log by default ({DEFAULT_ERF_LOG_PATH}) instead of scx_stairs",
    )
    args = parser.parse_args()

    if args.erf:
        default_log_path = DEFAULT_ERF_LOG_PATH
        source_name = "scx_erf"
    elif args.scheduler:
        default_log_path = DEFAULT_SCHEDULER_LOG_PATH
        source_name = "scx_scheduler"
    else:
        default_log_path = DEFAULT_STAIRS_LOG_PATH
        source_name = "scx_stairs"

    log_path = Path(args.file_path) if args.file_path else default_log_path
    if not log_path.exists():
        print(f"Log file not found: {log_path}", file=sys.stderr)
        return 1

    try:
        time_range = parse_time_range(args.time_range) if args.time_range else None
        cpus, available_metrics, rows = load_log_rows(log_path)
        metrics = select_metrics(available_metrics, args.debug)
        if args.cpu is not None and args.cpu not in cpus:
            raise ValueError(
                f"CPU {args.cpu} is not present in the log; available CPUs: {', '.join(map(str, cpus))}"
            )

        rows = filter_rows(rows, time_range)
        if not rows:
            raise ValueError("no samples in the selected time range")

        plot_rows(rows, cpus, metrics, time_range, args.cpu, log_path,
                  source_name)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
