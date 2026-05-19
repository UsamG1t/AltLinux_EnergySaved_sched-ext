import argparse
import csv
import math
import re
import sys
from dataclasses import dataclass
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

SCHEDULE_LINE_COLOR = "#7c3aed"
SCHEDULE_TEXT_COLOR = "#4c1d95"
SCHEDULE_LINE_WIDTH = 6.0


@dataclass(frozen=True)
class ScheduleEntry:
    task_id: int
    cpu: int
    freq_mhz: float
    start_sec: float
    end_sec: float
    step_idx: int


@dataclass(frozen=True)
class RowSpec:
    kind: str
    title: str
    metrics: tuple[str, ...] = ()


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


def parse_cpu_selection(spec: str, available_cpus: list[int]) -> list[int]:
    selected: set[int] = set()

    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue

        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if end < start:
                raise ValueError(f"invalid CPU range: {token}")
            for cpu in range(start, end + 1):
                selected.add(cpu)
        else:
            selected.add(int(token))

    if not selected:
        raise ValueError("CPU selection is empty")

    missing = sorted(cpu for cpu in selected if cpu not in available_cpus)
    if missing:
        raise ValueError(
            f"CPUs {', '.join(map(str, missing))} are not present in the log; "
            f"available CPUs: {', '.join(map(str, available_cpus))}"
        )

    return sorted(selected)


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


def select_default_metrics(available_metrics: tuple[str, ...]) -> tuple[str, ...]:
    if "policy" in available_metrics:
        return ("policy",)
    if "scaling" in available_metrics:
        return ("scaling",)
    if "avg" in available_metrics:
        return ("avg",)
    return available_metrics


def build_row_specs(available_metrics: tuple[str, ...],
                    main_mode: bool,
                    debug_mode: bool,
                    have_schedule: bool) -> list[RowSpec]:
    row_specs: list[RowSpec] = []

    if main_mode:
        row_specs.append(RowSpec("metrics", "policy_step(time_in_state)", ("policy",)))
        row_specs.append(RowSpec("metrics", "scaling_cur_freq", ("scaling",)))
    elif debug_mode:
        row_specs.append(RowSpec("metrics", "observed frequencies", available_metrics))
    else:
        row_specs.append(
            RowSpec("metrics", METRIC_LABELS[select_default_metrics(available_metrics)[0]],
                    select_default_metrics(available_metrics))
        )

    if have_schedule:
        row_specs.append(RowSpec("schedule", "planned schedule"))

    return row_specs


def filter_rows(rows: list[dict[str, float]],
                time_range: tuple[float, float] | None) -> list[dict[str, float]]:
    if time_range is None:
        return rows

    start, end = time_range
    return [row for row in rows if start <= row["elapsed_sec"] <= end]


def parse_schedule_file(path: Path) -> dict[int, list[ScheduleEntry]]:
    schedule_by_cpu: dict[int, list[ScheduleEntry]] = {}

    with path.open("r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if not line[0].isdigit():
                continue

            parts = line.split()
            if len(parts) < 10:
                raise ValueError(f"invalid schedule line: {raw_line.rstrip()}")

            task_id = int(parts[0])
            cpu = int(parts[3])
            step_idx = int(parts[4])
            freq_khz = int(parts[5])
            start_ns = int(parts[8])
            duration_ns = int(parts[9])

            entry = ScheduleEntry(
                task_id=task_id,
                cpu=cpu,
                freq_mhz=freq_khz / 1000.0,
                start_sec=start_ns / 1_000_000_000.0,
                end_sec=(start_ns + duration_ns) / 1_000_000_000.0,
                step_idx=step_idx,
            )
            schedule_by_cpu.setdefault(cpu, []).append(entry)

    for cpu_entries in schedule_by_cpu.values():
        cpu_entries.sort(key=lambda entry: (entry.start_sec, entry.end_sec, entry.task_id))

    return schedule_by_cpu


def filter_schedule(schedule_by_cpu: dict[int, list[ScheduleEntry]],
                    cpus: list[int],
                    time_range: tuple[float, float] | None) -> dict[int, list[ScheduleEntry]]:
    filtered: dict[int, list[ScheduleEntry]] = {cpu: [] for cpu in cpus}

    for cpu in cpus:
        for entry in schedule_by_cpu.get(cpu, []):
            start_sec = entry.start_sec
            end_sec = entry.end_sec

            if time_range is not None:
                start_limit, end_limit = time_range
                if end_sec < start_limit or start_sec > end_limit:
                    continue
                start_sec = max(start_sec, start_limit)
                end_sec = min(end_sec, end_limit)

            filtered[cpu].append(
                ScheduleEntry(
                    task_id=entry.task_id,
                    cpu=entry.cpu,
                    freq_mhz=entry.freq_mhz,
                    start_sec=start_sec,
                    end_sec=end_sec,
                    step_idx=entry.step_idx,
                )
            )

    return filtered


def finite_metric_values(rows: list[dict[str, float]], cpus: list[int],
                         metrics: tuple[str, ...]) -> list[float]:
    values = []

    for row in rows:
        for cpu in cpus:
            for metric in metrics:
                value = row.get(metric_field(cpu, metric), math.nan)
                if math.isfinite(value):
                    values.append(value)

    return values


def finite_schedule_values(schedule_by_cpu: dict[int, list[ScheduleEntry]],
                           cpus: list[int]) -> list[float]:
    values = []
    for cpu in cpus:
        for entry in schedule_by_cpu.get(cpu, []):
            values.append(entry.freq_mhz)
    return values


def gather_all_values(rows: list[dict[str, float]],
                      cpus: list[int],
                      row_specs: list[RowSpec],
                      schedule_by_cpu: dict[int, list[ScheduleEntry]]) -> list[float]:
    values = []

    for row_spec in row_specs:
        if row_spec.kind == "metrics":
            values.extend(finite_metric_values(rows, cpus, row_spec.metrics))
        elif row_spec.kind == "schedule":
            values.extend(finite_schedule_values(schedule_by_cpu, cpus))

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
        value = row.get(metric_field(cpu, metric), math.nan)
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


def cpu_suffix(display_cpus: list[int]) -> str:
    if not display_cpus:
        return ""
    if len(display_cpus) == 1:
        return f"_cpu{display_cpus[0]}"
    return "_cpu" + "-".join(map(str, display_cpus))


def svg_output_path(log_path: Path, display_cpus: list[int]) -> Path:
    return log_path.with_name(f"{log_path.stem}{cpu_suffix(display_cpus)}.svg")


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


def metric_legend_metrics(row_spec: RowSpec) -> tuple[str, ...]:
    return tuple(metric for metric in METRIC_ORDER if metric in row_spec.metrics)


def render_svg_metric_legend(parts: list[str], metrics: tuple[str, ...],
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
        x += 132.0


def render_svg_axes(parts: list[str], origin_x: float, origin_y: float,
                    width: float, height: float,
                    limits: tuple[float, float],
                    x_limits: tuple[float, float]) -> tuple[float, float, float, float]:
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

    parts.append(
        f'<rect x="{origin_x:.1f}" y="{origin_y:.1f}" width="{width:.1f}" height="{height:.1f}" '
        'fill="#ffffff" stroke="#d7dde5" stroke-width="1"/>'
    )

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

    return plot_x, plot_y, plot_width, plot_height


def render_svg_metric_panel(parts: list[str], rows: list[dict[str, float]], cpu: int,
                            row_spec: RowSpec, limits: tuple[float, float],
                            x_limits: tuple[float, float], origin_x: float,
                            origin_y: float, width: float, height: float) -> None:
    metrics = metric_legend_metrics(row_spec)
    has_data = False

    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(f"CPU {cpu} · {row_spec.title}")}</text>'
    )
    render_svg_metric_legend(parts, metrics, origin_x + 18.0, origin_y + 32.0)
    plot_x, plot_y, plot_width, plot_height = render_svg_axes(
        parts, origin_x, origin_y, width, height, limits, x_limits
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


def render_svg_schedule_panel(parts: list[str],
                              schedule_by_cpu: dict[int, list[ScheduleEntry]],
                              cpu: int,
                              limits: tuple[float, float],
                              x_limits: tuple[float, float],
                              origin_x: float, origin_y: float,
                              width: float, height: float) -> None:
    entries = schedule_by_cpu.get(cpu, [])

    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(f"CPU {cpu} · planned schedule")}</text>'
    )
    plot_x, plot_y, plot_width, plot_height = render_svg_axes(
        parts, origin_x, origin_y, width, height, limits, x_limits
    )

    if not entries:
        parts.append(
            f'<text x="{plot_x + plot_width / 2:.1f}" y="{plot_y + plot_height / 2:.1f}" '
            'font-family="sans-serif" font-size="13" text-anchor="middle" fill="#64748b">'
            'No scheduled tasks</text>'
        )
        return

    freq_span = max(limits[1] - limits[0], 1.0)
    label_threshold = max((x_limits[1] - x_limits[0]) * 0.08, 0.6)

    for entry in entries:
        x1 = plot_x + map_x(entry.start_sec, x_limits[0], x_limits[1], plot_width)
        x2 = plot_x + map_x(entry.end_sec, x_limits[0], x_limits[1], plot_width)
        y = plot_y + map_y(entry.freq_mhz, limits[0], limits[1], plot_height)
        label_y = plot_y + map_y(entry.freq_mhz + freq_span * 0.03,
                                 limits[0], limits[1], plot_height)

        parts.append(
            f'<line x1="{x1:.1f}" y1="{y:.1f}" x2="{x2:.1f}" y2="{y:.1f}" '
            f'stroke="{SCHEDULE_LINE_COLOR}" stroke-width="{SCHEDULE_LINE_WIDTH:.1f}" '
            'stroke-linecap="round"/>'
        )
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y - 4:.1f}" x2="{x1:.1f}" y2="{y + 4:.1f}" '
            f'stroke="{SCHEDULE_LINE_COLOR}" stroke-width="1.5"/>'
        )
        parts.append(
            f'<line x1="{x2:.1f}" y1="{y - 4:.1f}" x2="{x2:.1f}" y2="{y + 4:.1f}" '
            f'stroke="{SCHEDULE_LINE_COLOR}" stroke-width="1.5"/>'
        )

        if entry.end_sec - entry.start_sec >= label_threshold:
            parts.append(
                f'<text x="{(x1 + x2) / 2:.1f}" y="{label_y:.1f}" '
                'font-family="sans-serif" font-size="11" text-anchor="middle" '
                f'fill="{SCHEDULE_TEXT_COLOR}">{escape(f"t{entry.task_id}")}</text>'
            )


def render_svg(rows: list[dict[str, float]], cpus: list[int],
               row_specs: list[RowSpec],
               schedule_by_cpu: dict[int, list[ScheduleEntry]],
               time_range: tuple[float, float] | None,
               output_path: Path, source_name: str) -> Path:
    values = gather_all_values(rows, cpus, row_specs, schedule_by_cpu)
    if not values:
        raise ValueError("no finite frequency samples or schedule entries in the selected range")

    limits = y_limits(values)
    x_limits = compute_x_limits(rows, schedule_by_cpu, cpus, time_range)
    title = build_figure_title(source_name, time_range, len(cpus), row_specs)

    panel_width = 540.0
    panel_height = 320.0
    gap_x = 40.0
    gap_y = 40.0
    margin_x = 40.0
    top = 70.0

    width = margin_x * 2 + len(cpus) * panel_width + max(len(cpus) - 1, 0) * gap_x
    height = top + len(row_specs) * panel_height + max(len(row_specs) - 1, 0) * gap_y + 40.0

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        f'<text x="{width / 2:.1f}" y="34" font-family="sans-serif" font-size="20" '
        f'font-weight="bold" text-anchor="middle">{escape(title)}</text>',
    ]

    for row_idx, row_spec in enumerate(row_specs):
        for col_idx, cpu in enumerate(cpus):
            origin_x = margin_x + col_idx * (panel_width + gap_x)
            origin_y = top + row_idx * (panel_height + gap_y)

            if row_spec.kind == "metrics":
                render_svg_metric_panel(
                    parts, rows, cpu, row_spec, limits, x_limits,
                    origin_x, origin_y, panel_width, panel_height,
                )
            else:
                render_svg_schedule_panel(
                    parts, schedule_by_cpu, cpu, limits, x_limits,
                    origin_x, origin_y, panel_width, panel_height,
                )

    parts.append("</svg>")
    return write_svg(output_path, "\n".join(parts))


def plot_metric_axis(ax, rows: list[dict[str, float]], cpu: int,
                     row_spec: RowSpec, limits: tuple[float, float]) -> None:
    has_data = False
    metrics = metric_legend_metrics(row_spec)

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
    elif len(metrics) > 1:
        ax.legend(loc="upper right", fontsize=9)

    ax.set_ylim(*limits)
    ax.grid(True, linestyle="--", alpha=0.5)


def plot_schedule_axis(ax, schedule_by_cpu: dict[int, list[ScheduleEntry]],
                       cpu: int, limits: tuple[float, float],
                       x_limits: tuple[float, float]) -> None:
    entries = schedule_by_cpu.get(cpu, [])
    if not entries:
        ax.text(0.5, 0.5, "No scheduled tasks", transform=ax.transAxes,
                ha="center", va="center")
        ax.set_ylim(*limits)
        ax.grid(True, linestyle="--", alpha=0.5)
        return

    freq_span = max(limits[1] - limits[0], 1.0)
    label_threshold = max((x_limits[1] - x_limits[0]) * 0.08, 0.6)

    for entry in entries:
        ax.hlines(
            entry.freq_mhz,
            entry.start_sec,
            entry.end_sec,
            colors=SCHEDULE_LINE_COLOR,
            linewidth=SCHEDULE_LINE_WIDTH,
        )
        ax.vlines(
            [entry.start_sec, entry.end_sec],
            entry.freq_mhz - freq_span * 0.012,
            entry.freq_mhz + freq_span * 0.012,
            colors=SCHEDULE_LINE_COLOR,
            linewidth=1.3,
        )

        if entry.end_sec - entry.start_sec >= label_threshold:
            ax.text(
                (entry.start_sec + entry.end_sec) / 2.0,
                entry.freq_mhz + freq_span * 0.03,
                f"t{entry.task_id}",
                ha="center",
                va="bottom",
                fontsize=8,
                color=SCHEDULE_TEXT_COLOR,
            )

    ax.set_ylim(*limits)
    ax.grid(True, linestyle="--", alpha=0.5)


def compute_x_limits(rows: list[dict[str, float]],
                     schedule_by_cpu: dict[int, list[ScheduleEntry]],
                     cpus: list[int],
                     time_range: tuple[float, float] | None) -> tuple[float, float]:
    if time_range is not None:
        return time_range

    start = rows[0]["elapsed_sec"]
    end = rows[-1]["elapsed_sec"]

    for cpu in cpus:
        for entry in schedule_by_cpu.get(cpu, []):
            start = min(start, entry.start_sec)
            end = max(end, entry.end_sec)

    return start, end


def build_figure_title(source_name: str,
                       time_range: tuple[float, float] | None,
                       nr_cpus: int,
                       row_specs: list[RowSpec]) -> str:
    if nr_cpus == 1:
        title = f"{source_name} analysis"
    else:
        title = f"{source_name} analysis for selected CPUs"

    if time_range is not None:
        title += f" ({time_range[0]:g}-{time_range[1]:g} s)"

    if any(row.kind == "schedule" for row in row_specs):
        title += " with planned schedule"

    return title


def plot_rows(rows: list[dict[str, float]], cpus: list[int],
              row_specs: list[RowSpec],
              schedule_by_cpu: dict[int, list[ScheduleEntry]],
              time_range: tuple[float, float] | None,
              log_path: Path, source_name: str) -> None:
    plt = import_pyplot()
    if plt is None:
        output_path = render_svg(
            rows,
            cpus,
            row_specs,
            schedule_by_cpu,
            time_range,
            svg_output_path(log_path, cpus),
            source_name,
        )
        print(f"matplotlib is not installed, SVG graph saved to {output_path}")
        return

    values = gather_all_values(rows, cpus, row_specs, schedule_by_cpu)
    if not values:
        raise ValueError("no finite frequency samples or schedule entries in the selected range")

    limits = y_limits(values)
    x_limits = compute_x_limits(rows, schedule_by_cpu, cpus, time_range)

    nrows = len(row_specs)
    ncols = len(cpus)
    fig_width = max(6.0, 5.4 * ncols)
    fig_height = max(3.4, 2.9 * nrows + 0.8)
    fig, axes = plt.subplots(
        nrows,
        ncols,
        figsize=(fig_width, fig_height),
        sharex=True,
        squeeze=False,
    )

    for row_idx, row_spec in enumerate(row_specs):
        for col_idx, cpu in enumerate(cpus):
            ax = axes[row_idx][col_idx]
            if row_spec.kind == "metrics":
                plot_metric_axis(ax, rows, cpu, row_spec, limits)
            else:
                plot_schedule_axis(ax, schedule_by_cpu, cpu, limits, x_limits)

            ax.set_xlim(*x_limits)
            ax.set_title(f"CPU {cpu} · {row_spec.title}")
            ax.set_ylabel("Frequency (MHz)")
            if row_idx == nrows - 1:
                ax.set_xlabel("Time (s)")

    fig.suptitle(build_figure_title(source_name, time_range, len(cpus), row_specs))
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
        dest="cpu_selection",
        help="Show only selected CPUs; supports values like 2,3 or ranges like 2-3,6-7",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--debug",
        action="store_true",
        help="Overlay all available observed lines on one row",
    )
    mode_group.add_argument(
        "--main",
        action="store_true",
        help="Show policy on the first row and scaling_cur_freq on the second row",
    )
    parser.add_argument(
        "--input",
        dest="input_schedule",
        help="Path to the static schedule file produced for the scheduler run",
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

    schedule_path = Path(args.input_schedule) if args.input_schedule else None
    if schedule_path is not None and not schedule_path.exists():
        print(f"Schedule file not found: {schedule_path}", file=sys.stderr)
        return 1

    try:
        time_range = parse_time_range(args.time_range) if args.time_range else None
        available_cpus, available_metrics, rows = load_log_rows(log_path)
        selected_cpus = (
            parse_cpu_selection(args.cpu_selection, available_cpus)
            if args.cpu_selection
            else available_cpus
        )

        rows = filter_rows(rows, time_range)
        if not rows:
            raise ValueError("no samples in the selected time range")

        raw_schedule = parse_schedule_file(schedule_path) if schedule_path else {}
        schedule_by_cpu = filter_schedule(raw_schedule, selected_cpus, time_range)
        row_specs = build_row_specs(
            available_metrics,
            main_mode=args.main,
            debug_mode=args.debug,
            have_schedule=bool(schedule_path),
        )

        plot_rows(rows, selected_cpus, row_specs, schedule_by_cpu, time_range,
                  log_path, source_name)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
