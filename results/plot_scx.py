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
DEFAULT_BORDERS_LOG_PATH = Path("./results/scx_borders/latest.csv")

CPU_METRIC_RE = re.compile(r"^cpu(\d+)_(policy|scaling|avg)_mhz$")
CPU_OLD_RE = re.compile(r"^cpu(\d+)_mhz$")
RAPL_FIELD_RE = re.compile(r"^rapl_(.+)_(energy_j|power_w)$")

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

# RAPL rows are machine-wide: one full-width panel below the per-CPU panels.
RAPL_KINDS = ("power", "energy")
RAPL_FIELD_SUFFIXES = {
    "power": "power_w",
    "energy": "energy_j",
}
RAPL_TITLES = {
    "power": "RAPL instantaneous power",
    "energy": "RAPL cumulative energy",
}
RAPL_Y_LABELS = {
    "power": "Мощность (Вт)",
    "energy": "Энергия (Дж)",
}
RAPL_COLORS = ("#b91c1c", "#1d4ed8", "#15803d", "#a16207", "#7c3aed", "#0e7490")
RAPL_LINE_WIDTH = 1.8
FREQ_Y_LABEL = "Тактовая частота (МГц)"


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


def parse_float_or_nan(value: str | None) -> float:
    if value is None:
        return math.nan
    text = value.strip()
    if not text or text.lower() in {"none", "nan"}:
        return math.nan
    return float(text)


def rapl_field(domain: str, kind: str) -> str:
    return f"rapl_{domain}_{RAPL_FIELD_SUFFIXES[kind]}"


def find_rapl_domains(fieldnames: list[str]) -> tuple[str, ...]:
    domains: list[str] = []

    for field in fieldnames:
        match = RAPL_FIELD_RE.match(field)
        if match and match.group(1) not in domains:
            domains.append(match.group(1))

    return tuple(domains)


def load_log_rows(path: Path) -> tuple[list[int], tuple[str, ...], tuple[str, ...],
                                       list[dict[str, float]]]:
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
        rapl_domains = find_rapl_domains(reader.fieldnames)

        for raw_row in reader:
            elapsed_text = raw_row.get("elapsed_sec")
            if not elapsed_text:
                continue
            try:
                elapsed_sec = float(elapsed_text)
            except ValueError:
                continue

            row = {"elapsed_sec": elapsed_sec}
            for cpu in cpus:
                for metric in metrics:
                    field = columns[cpu].get(metric)
                    key = metric_field(cpu, metric)
                    if field is None:
                        row[key] = math.nan
                        continue

                    value = raw_row.get(field, "")
                    row[key] = parse_float_or_nan(value)
            for domain in rapl_domains:
                for kind in RAPL_KINDS:
                    key = rapl_field(domain, kind)
                    row[key] = parse_float_or_nan(raw_row.get(key) or "")
            rows.append(row)

    return cpus, metrics, rapl_domains, rows


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
                    have_schedule: bool,
                    power_mode: bool = False) -> list[RowSpec]:
    row_specs: list[RowSpec] = []

    if have_schedule:
        row_specs.append(RowSpec("schedule", "planned schedule"))

    if main_mode:
        if "policy" in available_metrics:
            row_specs.append(RowSpec("metrics", "policy_step(time_in_state)", ("policy",)))
        if "scaling" in available_metrics:
            row_specs.append(RowSpec("metrics", "scaling_cur_freq", ("scaling",)))
    elif debug_mode:
        if available_metrics:
            row_specs.append(RowSpec("metrics", "observed frequencies", available_metrics))
    else:
        selected_metrics = select_default_metrics(available_metrics)
        if selected_metrics:
            row_specs.append(
                RowSpec("metrics", METRIC_LABELS[selected_metrics[0]], selected_metrics)
            )

    if power_mode:
        for kind in RAPL_KINDS:
            row_specs.append(RowSpec(kind, RAPL_TITLES[kind]))

    return row_specs


def is_rapl_row(row_spec: RowSpec) -> bool:
    return row_spec.kind in RAPL_KINDS


def rapl_series(rows: list[dict[str, float]], domain: str,
                kind: str) -> tuple[list[float], list[float]]:
    times = []
    values = []
    key = rapl_field(domain, kind)

    for row in rows:
        value = row.get(key, math.nan)
        if not math.isfinite(value):
            continue
        times.append(row["elapsed_sec"])
        values.append(value)

    return times, values


def rapl_domains_with_data(rows: list[dict[str, float]],
                           rapl_domains: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        domain for domain in rapl_domains
        if any(rapl_series(rows, domain, kind)[0] for kind in RAPL_KINDS)
    )


def rapl_y_limits(rows: list[dict[str, float]], rapl_domains: tuple[str, ...],
                  kind: str) -> tuple[float, float]:
    values = [
        value
        for domain in rapl_domains
        for value in rapl_series(rows, domain, kind)[1]
    ]
    if not values:
        return 0.0, 1.0

    high = max(values)
    if high <= 0.0:
        return 0.0, 1.0
    return 0.0, high * 1.08


def rapl_color(index: int) -> str:
    return RAPL_COLORS[index % len(RAPL_COLORS)]


def rapl_legend_label(rows: list[dict[str, float]], domain: str, kind: str) -> str:
    if kind != "energy":
        return domain

    # Energy consumed inside the displayed window (whole run without -t).
    _, values = rapl_series(rows, domain, "energy")
    if not values:
        return domain
    return f"{domain}: {values[-1] - values[0]:.2f} J"


def filter_rows(rows: list[dict[str, float]],
                time_range: tuple[float, float] | None) -> list[dict[str, float]]:
    if time_range is None:
        return rows

    start, end = time_range
    return [row for row in rows if start <= row["elapsed_sec"] <= end]


def parse_schedule_file(
    path: Path,
) -> tuple[float, dict[int, list[ScheduleEntry]]]:
    period_sec: float | None = None
    schedule_by_cpu: dict[int, list[ScheduleEntry]] = {}

    with path.open("r", encoding="utf-8") as file:
        for line_no, raw_line in enumerate(file, 1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            if line.startswith("deadline_ms"):
                parts = line.replace(":", " ").replace("=", " ").split()
                if len(parts) != 2:
                    raise ValueError(
                        f"{path}:{line_no}: invalid deadline_ms line"
                    )
                period_ms = int(parts[1])
                if period_ms <= 0:
                    raise ValueError(
                        f"{path}:{line_no}: deadline_ms must be positive"
                    )
                period_sec = period_ms / 1000.0
                continue

            if not line[0].isdigit():
                continue

            parts = line.split()
            if len(parts) == 10:
                start_idx = 8
                duration_idx = 9
            elif len(parts) == 9:
                start_idx = 7
                duration_idx = 8
            else:
                raise ValueError(f"invalid schedule line: {raw_line.rstrip()}")

            task_id = int(parts[0])
            cpu = int(parts[3])
            step_idx = int(parts[4])
            freq_khz = int(parts[5])
            start_ns = int(parts[start_idx])
            duration_ns = int(parts[duration_idx])

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

    if period_sec is None:
        raise ValueError(f"{path}: schedule is missing deadline_ms")

    return period_sec, schedule_by_cpu


def repeat_schedule(
    schedule_by_cpu: dict[int, list[ScheduleEntry]],
    period_sec: float,
    execution_start: float,
    execution_end: float,
) -> dict[int, list[ScheduleEntry]]:
    repeated: dict[int, list[ScheduleEntry]] = {
        cpu: [] for cpu in schedule_by_cpu
    }
    first_cycle = max(0, math.floor(execution_start / period_sec))
    last_cycle = max(first_cycle, math.floor(execution_end / period_sec))

    for cpu, entries in schedule_by_cpu.items():
        for cycle_index in range(first_cycle, last_cycle + 1):
            offset = cycle_index * period_sec
            for entry in entries:
                start_sec = entry.start_sec + offset
                end_sec = entry.end_sec + offset
                if end_sec <= execution_start or start_sec >= execution_end:
                    continue

                repeated[cpu].append(
                    ScheduleEntry(
                        task_id=entry.task_id,
                        cpu=entry.cpu,
                        freq_mhz=entry.freq_mhz,
                        start_sec=max(start_sec, execution_start),
                        end_sec=min(end_sec, execution_end),
                        step_idx=entry.step_idx,
                    )
                )

    return repeated


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


def metrics_with_finite_values(rows: list[dict[str, float]], cpus: list[int],
                               metrics: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        metric for metric in metrics
        if finite_metric_values(rows, cpus, (metric,))
    )


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


def step_points_pre(times: list[float], values: list[float]) -> list[tuple[float, float]]:
    # values[i] is an average over (times[i - 1], times[i]]
    points = []
    if not times:
        return points

    points.append((times[0], values[0]))
    for index in range(1, len(times)):
        points.append((times[index - 1], values[index]))
        points.append((times[index], values[index]))

    return points


def tick_format_for(limits: tuple[float, float]) -> str:
    span = limits[1] - limits[0]
    if span >= 50.0:
        return "{:.0f}"
    if span >= 5.0:
        return "{:.1f}"
    return "{:.2f}"


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


def render_svg_legend(parts: list[str], entries: list[tuple[str, str]],
                      origin_x: float, origin_y: float) -> None:
    x = origin_x

    for label, color in entries:
        parts.append(
            f'<line x1="{x:.1f}" y1="{origin_y:.1f}" x2="{x + 18:.1f}" y2="{origin_y:.1f}" '
            f'stroke="{color}" stroke-width="3"/>'
        )
        parts.append(
            f'<text x="{x + 24:.1f}" y="{origin_y + 4:.1f}" font-family="sans-serif" '
            f'font-size="11">{escape(label)}</text>'
        )
        x += 40.0 + 7.0 * len(label)


def render_svg_axes(parts: list[str], origin_x: float, origin_y: float,
                    width: float, height: float,
                    limits: tuple[float, float],
                    x_limits: tuple[float, float],
                    y_label: str = FREQ_Y_LABEL,
                    tick_format: str = "{:.0f}") -> tuple[float, float, float, float]:
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
            f'font-size="11" text-anchor="end">{tick_format.format(tick)}</text>'
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
        'font-family="sans-serif" font-size="12" text-anchor="middle">Время (с)</text>'
    )
    parts.append(
        f'<text x="{origin_x + 16:.1f}" y="{plot_y + plot_height / 2:.1f}" '
        'font-family="sans-serif" font-size="12" text-anchor="middle" '
        f'transform="rotate(-90 {origin_x + 16:.1f} {plot_y + plot_height / 2:.1f})">'
        f'{escape(y_label)}</text>'
    )

    return plot_x, plot_y, plot_width, plot_height


def render_svg_metric_panel(parts: list[str], rows: list[dict[str, float]], cpu: int,
                            row_spec: RowSpec, limits: tuple[float, float],
                            x_limits: tuple[float, float], origin_x: float,
                            origin_y: float, width: float, height: float) -> None:
    metrics = metric_legend_metrics(row_spec)
    has_data = False

    # Axes first: render_svg_axes paints the opaque panel background.
    plot_x, plot_y, plot_width, plot_height = render_svg_axes(
        parts, origin_x, origin_y, width, height, limits, x_limits
    )
    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(f"CPU {cpu} · {row_spec.title}")}</text>'
    )
    render_svg_metric_legend(parts, metrics, origin_x + 18.0, origin_y + 32.0)

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

    # Axes first: render_svg_axes paints the opaque panel background.
    plot_x, plot_y, plot_width, plot_height = render_svg_axes(
        parts, origin_x, origin_y, width, height, limits, x_limits
    )
    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(f"CPU {cpu} · planned schedule")}</text>'
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


def render_svg_rapl_panel(parts: list[str], rows: list[dict[str, float]],
                          rapl_domains: tuple[str, ...], row_spec: RowSpec,
                          x_limits: tuple[float, float], origin_x: float,
                          origin_y: float, width: float, height: float) -> None:
    kind = row_spec.kind
    limits = rapl_y_limits(rows, rapl_domains, kind)
    has_data = False

    # Axes first: render_svg_axes paints the opaque panel background.
    plot_x, plot_y, plot_width, plot_height = render_svg_axes(
        parts, origin_x, origin_y, width, height, limits, x_limits,
        y_label=RAPL_Y_LABELS[kind], tick_format=tick_format_for(limits),
    )
    parts.append(
        f'<text x="{origin_x + width / 2:.1f}" y="{origin_y + 18:.1f}" '
        'font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">'
        f'{escape(row_spec.title)}</text>'
    )
    render_svg_legend(
        parts,
        [(rapl_legend_label(rows, domain, kind), rapl_color(index))
         for index, domain in enumerate(rapl_domains)],
        origin_x + 18.0, origin_y + 32.0,
    )

    for index, domain in enumerate(rapl_domains):
        times, values = rapl_series(rows, domain, kind)
        if not times:
            continue

        has_data = True
        points = step_points_pre(times, values) if kind == "power" else list(zip(times, values))
        svg_points = " ".join(
            f"{plot_x + map_x(time, x_limits[0], x_limits[1], plot_width):.1f},"
            f"{plot_y + map_y(value, limits[0], limits[1], plot_height):.1f}"
            for time, value in points
        )
        parts.append(
            f'<polyline fill="none" stroke="{rapl_color(index)}" '
            f'stroke-width="{RAPL_LINE_WIDTH:.1f}" points="{svg_points}"/>'
        )

    if not has_data:
        parts.append(
            f'<text x="{plot_x + plot_width / 2:.1f}" y="{plot_y + plot_height / 2:.1f}" '
            'font-family="sans-serif" font-size="13" text-anchor="middle" fill="#64748b">'
            'No data</text>'
        )


def frequency_limits(rows: list[dict[str, float]], cpus: list[int],
                     row_specs: list[RowSpec],
                     schedule_by_cpu: dict[int, list[ScheduleEntry]]) -> tuple[float, float]:
    values = gather_all_values(rows, cpus, row_specs, schedule_by_cpu)
    if values:
        return y_limits(values)
    if any(not is_rapl_row(row_spec) for row_spec in row_specs):
        raise ValueError("no finite frequency samples or schedule entries in the selected range")
    return 0.0, 1.0


def render_svg(rows: list[dict[str, float]], cpus: list[int],
               row_specs: list[RowSpec],
               schedule_by_cpu: dict[int, list[ScheduleEntry]],
               time_range: tuple[float, float] | None,
               output_path: Path, source_name: str,
               rapl_domains: tuple[str, ...] = ()) -> Path:
    limits = frequency_limits(rows, cpus, row_specs, schedule_by_cpu)
    x_limits = compute_x_limits(rows, schedule_by_cpu, cpus, time_range)
    panel_width = 540.0
    panel_height = 320.0
    gap_x = 40.0
    gap_y = 40.0
    margin_x = 40.0
    top = 40.0

    width = margin_x * 2 + len(cpus) * panel_width + max(len(cpus) - 1, 0) * gap_x
    height = top + len(row_specs) * panel_height + max(len(row_specs) - 1, 0) * gap_y + 40.0

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
    ]

    for row_idx, row_spec in enumerate(row_specs):
        if is_rapl_row(row_spec):
            render_svg_rapl_panel(
                parts, rows, rapl_domains, row_spec, x_limits,
                margin_x, top + row_idx * (panel_height + gap_y),
                width - margin_x * 2, panel_height,
            )
            continue

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


def plot_rapl_axis(ax, rows: list[dict[str, float]], rapl_domains: tuple[str, ...],
                   row_spec: RowSpec) -> None:
    kind = row_spec.kind
    has_data = False

    for index, domain in enumerate(rapl_domains):
        times, values = rapl_series(rows, domain, kind)
        if not times:
            continue

        has_data = True
        label = rapl_legend_label(rows, domain, kind)
        if kind == "power":
            ax.step(times, values, where="pre", color=rapl_color(index),
                    linewidth=RAPL_LINE_WIDTH, label=label)
        else:
            ax.plot(times, values, color=rapl_color(index),
                    linewidth=RAPL_LINE_WIDTH, label=label)

    if not has_data:
        ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                ha="center", va="center")
    else:
        ax.legend(loc="upper left", fontsize=9)

    ax.set_ylim(*rapl_y_limits(rows, rapl_domains, kind))
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


def plot_rows(rows: list[dict[str, float]], cpus: list[int],
              row_specs: list[RowSpec],
              schedule_by_cpu: dict[int, list[ScheduleEntry]],
              time_range: tuple[float, float] | None,
              log_path: Path, source_name: str,
              rapl_domains: tuple[str, ...] = (),
              output_path: Path | None = None) -> None:
    plt = import_pyplot()
    if plt is None:
        if output_path is not None and output_path.suffix.lower() != ".svg":
            raise ValueError(
                f"matplotlib is not installed, only .svg output is supported: {output_path}"
            )
        saved_path = render_svg(
            rows,
            cpus,
            row_specs,
            schedule_by_cpu,
            time_range,
            output_path or svg_output_path(log_path, cpus),
            source_name,
            rapl_domains,
        )
        print(f"matplotlib is not installed, SVG graph saved to {saved_path}")
        return

    limits = frequency_limits(rows, cpus, row_specs, schedule_by_cpu)
    x_limits = compute_x_limits(rows, schedule_by_cpu, cpus, time_range)

    nrows = len(row_specs)
    ncols = len(cpus)
    fig_width = max(6.0, 5.4 * ncols)
    fig_height = max(3.4, 2.9 * nrows + 0.8)
    fig = plt.figure(figsize=(fig_width, fig_height))
    grid = fig.add_gridspec(nrows, ncols)
    first_ax = None

    for row_idx, row_spec in enumerate(row_specs):
        if is_rapl_row(row_spec):
            row_cells = [(grid[row_idx, :], None)]
        else:
            row_cells = [(grid[row_idx, col_idx], cpu) for col_idx, cpu in enumerate(cpus)]

        for cell, cpu in row_cells:
            ax = fig.add_subplot(cell, sharex=first_ax)
            if first_ax is None:
                first_ax = ax

            if is_rapl_row(row_spec):
                plot_rapl_axis(ax, rows, rapl_domains, row_spec)
                ax.set_title(row_spec.title)
                ax.set_ylabel(RAPL_Y_LABELS[row_spec.kind])
            else:
                if row_spec.kind == "metrics":
                    plot_metric_axis(ax, rows, cpu, row_spec, limits)
                else:
                    plot_schedule_axis(ax, schedule_by_cpu, cpu, limits, x_limits)
                ax.set_title(f"CPU {cpu} · {row_spec.title}")
                ax.set_ylabel(FREQ_Y_LABEL)

            ax.set_xlim(*x_limits)
            if row_idx == nrows - 1:
                ax.set_xlabel("Время (с)")
    fig.tight_layout()

    if output_path is not None:
        fig.savefig(output_path, dpi=150)
        plt.close(fig)
        print(f"Graph saved to {output_path}")
        return

    plt.show()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Plot frequency and RAPL energy logs collected by scx_stairs, "
            "scx_scheduler, scx_erf, or scx_borders."
        )
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
    parser.add_argument(
        "--power",
        action="store_true",
        help="Add full-width rows with RAPL instantaneous power and cumulative energy",
    )
    parser.add_argument(
        "-o",
        dest="output_path",
        help="Save the graph to this file (.png, .svg, .pdf) instead of showing it",
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
    source_group.add_argument(
        "--borders",
        action="store_true",
        help=f"Use scx_borders log by default ({DEFAULT_BORDERS_LOG_PATH}) instead of scx_stairs",
    )
    args = parser.parse_args()

    if args.borders:
        default_log_path = DEFAULT_BORDERS_LOG_PATH
        source_name = "scx_borders"
    elif args.erf:
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
        available_cpus, available_metrics, rapl_domains, all_rows = load_log_rows(log_path)
        if not all_rows:
            raise ValueError("log file has no samples")
        if args.power and not rapl_domains:
            raise ValueError(f"log file has no RAPL columns: {log_path}")
        selected_cpus = (
            parse_cpu_selection(args.cpu_selection, available_cpus)
            if args.cpu_selection
            else available_cpus
        )

        execution_start = all_rows[0]["elapsed_sec"]
        execution_end = all_rows[-1]["elapsed_sec"]
        execution_duration = execution_end

        rows = filter_rows(all_rows, time_range)
        if not rows:
            raise ValueError("no samples in the selected time range")
        available_metrics = metrics_with_finite_values(
            rows, selected_cpus, available_metrics
        )
        rapl_domains = rapl_domains_with_data(rows, rapl_domains)

        raw_schedule: dict[int, list[ScheduleEntry]] = {}
        if schedule_path:
            period_sec, raw_schedule = parse_schedule_file(schedule_path)
            if execution_duration >= 3.0 * period_sec:
                raw_schedule = repeat_schedule(
                    raw_schedule,
                    period_sec,
                    execution_start,
                    execution_end,
                )

        schedule_by_cpu = filter_schedule(raw_schedule, selected_cpus, time_range)
        row_specs = build_row_specs(
            available_metrics,
            main_mode=args.main,
            debug_mode=args.debug,
            have_schedule=bool(schedule_path),
            power_mode=args.power,
        )

        output_path = Path(args.output_path) if args.output_path else None
        plot_rows(rows, selected_cpus, row_specs, schedule_by_cpu, time_range,
                  log_path, source_name, rapl_domains, output_path)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
