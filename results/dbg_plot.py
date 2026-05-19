import argparse
import math
import re
import sys
from dataclasses import dataclass
from html import escape
from pathlib import Path


SAMPLE_LINE_RE = re.compile(r"^t=\s*([0-9.]+)s\s+(.*)$")
SAMPLE_CPU_RE = re.compile(
    r"cpu(\d+)=\s*(n/a|[0-9.]+)\|\s*(n/a|[0-9.]+)/(n/a|[0-9.]+)MHz"
)
DBG_CPU_RE = re.compile(
    r"cpu(\d+)\[ev=(\S+)\s+perf=(\d+)\s+task=(\d+)\s+step=(\d+)\s+freq=(\d+)\s+"
    r"actor=(\S+)\s+plan=(\S+)\s+hits=(\d+)/(\d+)\s+keep=(\d+)\s+set=(\d+)\s+"
    r"z=(\d+)/(\d+)/(\d+)\]"
)

STATUS_COLORS = {
    "good": "#16a34a",
    "policy_lag": "#2563eb",
    "intercepted_hold": "#d97706",
    "intercepted_drop": "#dc2626",
    "freq_mismatch": "#9333ea",
    "idle_or_done": "#94a3b8",
    "unknown": "#64748b",
}

STATUS_LABELS = {
    "good": "all good",
    "policy_lag": "policy lags, actual freq looks OK",
    "intercepted_hold": "task was preempted, target frequency held",
    "intercepted_drop": "task was preempted, frequency dropped to zero",
    "freq_mismatch": "no interception, but target frequency mismatch",
    "idle_or_done": "idle or task finished",
    "unknown": "unknown / not enough data",
}

METRIC_COLORS = {
    "policy": "#1d4ed8",
    "scaling": "#0b6e4f",
    "avg": "#c2410c",
    "target": "#7c3aed",
}


@dataclass
class CpuSample:
    policy_mhz: float = math.nan
    scaling_mhz: float = math.nan
    avg_mhz: float = math.nan
    event: str = "-"
    perf_target: int = 0
    task_id: int = 0
    step_idx: int = 0
    target_mhz: float = 0.0
    actor_name: str = "-"
    actor_pid: int = 0
    plan_name: str = "-"
    plan_pid: int = 0
    plan_hits: int = 0
    unplanned_hits: int = 0
    keep_hits: int = 0
    set_hits: int = 0
    zero_run_hits: int = 0
    zero_stop_hits: int = 0
    zero_idle_hits: int = 0


@dataclass
class Sample:
    time_sec: float
    cpus: dict[int, CpuSample]


def parse_number(text: str) -> float:
    return math.nan if text == "n/a" else float(text)


def split_name_pid(token: str) -> tuple[str, int]:
    if "/" not in token:
        return token, 0

    name, pid_text = token.rsplit("/", 1)
    try:
        return name, int(pid_text)
    except ValueError:
        return token, 0


def parse_log(path: Path) -> tuple[list[int], list[Sample]]:
    samples: list[Sample] = []
    pending: Sample | None = None
    cpus_seen: set[int] = set()

    with path.open("r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.rstrip("\n")
            if not line:
                continue

            match = SAMPLE_LINE_RE.match(line)
            if match:
                if pending is not None:
                    samples.append(pending)

                sample = Sample(time_sec=float(match.group(1)), cpus={})
                cpu_blob = match.group(2)

                for cpu_match in SAMPLE_CPU_RE.finditer(cpu_blob):
                    cpu = int(cpu_match.group(1))
                    cpus_seen.add(cpu)
                    sample.cpus[cpu] = CpuSample(
                        policy_mhz=parse_number(cpu_match.group(2)),
                        scaling_mhz=parse_number(cpu_match.group(3)),
                        avg_mhz=parse_number(cpu_match.group(4)),
                    )

                pending = sample
                continue

            if line.startswith("dbg:") and pending is not None:
                for dbg_match in DBG_CPU_RE.finditer(line):
                    cpu = int(dbg_match.group(1))
                    cpus_seen.add(cpu)
                    actor_name, actor_pid = split_name_pid(dbg_match.group(7))
                    plan_name, plan_pid = split_name_pid(dbg_match.group(8))

                    state = pending.cpus.setdefault(cpu, CpuSample())
                    state.event = dbg_match.group(2)
                    state.perf_target = int(dbg_match.group(3))
                    state.task_id = int(dbg_match.group(4))
                    state.step_idx = int(dbg_match.group(5))
                    state.target_mhz = int(dbg_match.group(6)) / 1000.0
                    state.actor_name = actor_name
                    state.actor_pid = actor_pid
                    state.plan_name = plan_name
                    state.plan_pid = plan_pid
                    state.plan_hits = int(dbg_match.group(9))
                    state.unplanned_hits = int(dbg_match.group(10))
                    state.keep_hits = int(dbg_match.group(11))
                    state.set_hits = int(dbg_match.group(12))
                    state.zero_run_hits = int(dbg_match.group(13))
                    state.zero_stop_hits = int(dbg_match.group(14))
                    state.zero_idle_hits = int(dbg_match.group(15))

    if pending is not None:
        samples.append(pending)

    if not samples:
        raise ValueError("no samples found in dbg log")

    cpus = sorted(cpus_seen)
    if not cpus:
        raise ValueError("no CPU entries found in dbg log")

    return cpus, samples


def classify_sample(sample: CpuSample) -> str:
    if sample.event == "runhold":
        return "intercepted_hold"
    if sample.event == "run0":
        return "intercepted_drop"
    if sample.event in {"idle0", "stop0"} or sample.perf_target == 0:
        return "idle_or_done"
    if sample.event != "plan" or sample.target_mhz <= 0.0:
        return "unknown"

    tolerance = max(80.0, sample.target_mhz * 0.08)

    def ok(value: float) -> bool:
        return math.isfinite(value) and abs(value - sample.target_mhz) <= tolerance

    actual_ok = ok(sample.scaling_mhz) or ok(sample.avg_mhz)
    policy_ok = ok(sample.policy_mhz)

    if actual_ok and not policy_ok and math.isfinite(sample.policy_mhz):
        return "policy_lag"
    if actual_ok:
        return "good"
    return "freq_mismatch"


def value_limits(samples: list[Sample], cpus: list[int]) -> tuple[float, float]:
    values = []
    for sample in samples:
        for cpu in cpus:
            state = sample.cpus.get(cpu)
            if state is None:
                continue
            for value in (
                state.policy_mhz,
                state.scaling_mhz,
                state.avg_mhz,
                state.target_mhz if state.target_mhz > 0.0 else math.nan,
            ):
                if math.isfinite(value):
                    values.append(value)

    if not values:
        return 0.0, 1.0

    low = min(values)
    high = max(values)
    pad = max((high - low) * 0.05, 50.0) if not math.isclose(low, high) else max(low * 0.05, 50.0)
    return max(0.0, low - pad), high + pad


def sample_interval(samples: list[Sample]) -> float:
    if len(samples) < 2:
        return 0.1

    deltas = [
        samples[i + 1].time_sec - samples[i].time_sec
        for i in range(len(samples) - 1)
        if samples[i + 1].time_sec > samples[i].time_sec
    ]
    if not deltas:
        return 0.1

    deltas.sort()
    return deltas[len(deltas) // 2]


def event_annotation_text(state: CpuSample, status: str) -> str | None:
    if status == "intercepted_hold":
        return f"{state.actor_name}/{state.actor_pid}"
    if status == "intercepted_drop":
        return f"{state.actor_name}/{state.actor_pid}"
    if status == "freq_mismatch":
        return f"step {state.step_idx}"
    return None


def svg_output_path(path: Path) -> Path:
    return path.with_suffix(".analysis.svg")


def write_svg(output_path: Path, contents: str) -> Path:
    output_path.write_text(contents, encoding="utf-8")
    return output_path


def svg_x(time_sec: float, x0: float, width: float, t_min: float, t_max: float) -> float:
    if math.isclose(t_min, t_max):
        return x0 + width * 0.5
    return x0 + (time_sec - t_min) / (t_max - t_min) * width


def svg_y(value: float, y0: float, height: float, v_min: float, v_max: float) -> float:
    if math.isclose(v_min, v_max):
        return y0 + height * 0.5
    return y0 + height - (value - v_min) / (v_max - v_min) * height


def finite_segments(times: list[float], values: list[float]) -> list[list[tuple[float, float]]]:
    segments: list[list[tuple[float, float]]] = []
    current: list[tuple[float, float]] = []

    for time_sec, value in zip(times, values):
        if math.isfinite(value):
            current.append((time_sec, value))
        elif current:
            segments.append(current)
            current = []

    if current:
        segments.append(current)

    return segments


def render_svg_axes(parts: list[str], x0: float, y0: float, width: float, height: float,
                    t_min: float, t_max: float, v_min: float, v_max: float,
                    title: str, y_label: str) -> None:
    parts.append(
        f'<rect x="{x0:.1f}" y="{y0:.1f}" width="{width:.1f}" height="{height:.1f}" '
        'fill="white" stroke="#cbd5e1" stroke-width="1"/>'
    )
    parts.append(
        f'<text x="{x0 + width * 0.5:.1f}" y="{y0 - 12:.1f}" text-anchor="middle" '
        'font-size="14" font-weight="600" fill="#0f172a">'
        f'{escape(title)}</text>'
    )
    parts.append(
        f'<text x="{x0 - 42:.1f}" y="{y0 + height * 0.5:.1f}" text-anchor="middle" '
        'font-size="12" fill="#334155" transform="rotate(-90 {x0 - 42:.1f} {y0 + height * 0.5:.1f})">'
        f'{escape(y_label)}</text>'
    )

    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = y0 + height * frac
        value = v_max - (v_max - v_min) * frac
        parts.append(
            f'<line x1="{x0:.1f}" y1="{y:.1f}" x2="{x0 + width:.1f}" y2="{y:.1f}" '
            'stroke="#e2e8f0" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x0 - 8:.1f}" y="{y + 4:.1f}" text-anchor="end" '
            'font-size="11" fill="#475569">'
            f'{value:.0f}</text>'
        )

    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = x0 + width * frac
        time_value = t_min + (t_max - t_min) * frac
        parts.append(
            f'<line x1="{x:.1f}" y1="{y0:.1f}" x2="{x:.1f}" y2="{y0 + height:.1f}" '
            'stroke="#e2e8f0" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y0 + height + 16:.1f}" text-anchor="middle" '
            'font-size="11" fill="#475569">'
            f'{time_value:.1f}</text>'
        )


def render_svg_series(parts: list[str], times: list[float], values: list[float], *,
                      x0: float, y0: float, width: float, height: float,
                      t_min: float, t_max: float, v_min: float, v_max: float,
                      color: str, stroke_width: float, dasharray: str | None = None) -> None:
    for segment in finite_segments(times, values):
        if len(segment) < 2:
            continue

        svg_points = " ".join(
            f"{svg_x(time_sec, x0, width, t_min, t_max):.1f},{svg_y(value, y0, height, v_min, v_max):.1f}"
            for time_sec, value in segment
        )
        dash_attr = f' stroke-dasharray="{dasharray}"' if dasharray else ""
        parts.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="{stroke_width:.1f}"{dash_attr} '
            f'points="{svg_points}"/>'
        )


def render_svg_metric_legend(parts: list[str], entries: list[tuple[str, str, str | None]],
                             x0: float, y0: float) -> None:
    cursor_x = x0
    for label, color, dasharray in entries:
        dash_attr = f' stroke-dasharray="{dasharray}"' if dasharray else ""
        parts.append(
            f'<line x1="{cursor_x:.1f}" y1="{y0:.1f}" x2="{cursor_x + 16:.1f}" y2="{y0:.1f}" '
            f'stroke="{color}" stroke-width="2"{dash_attr}/>'
        )
        parts.append(
            f'<text x="{cursor_x + 22:.1f}" y="{y0 + 4:.1f}" font-size="11" fill="#334155">'
            f'{escape(label)}</text>'
        )
        cursor_x += 120


def render_svg_status_legend(parts: list[str], x0: float, y0: float) -> None:
    cursor_x = x0
    for key, color in STATUS_COLORS.items():
        parts.append(
            f'<rect x="{cursor_x:.1f}" y="{y0 - 10:.1f}" width="12" height="12" '
            f'fill="{color}" stroke="{color}"/>'
        )
        parts.append(
            f'<text x="{cursor_x + 18:.1f}" y="{y0:.1f}" font-size="11" fill="#334155">'
            f'{escape(STATUS_LABELS[key])}</text>'
        )
        cursor_x += 170


def render_svg_fallback(path: Path, cpus: list[int], samples: list[Sample]) -> Path:
    y_min, y_max = value_limits(samples, cpus)
    dt = sample_interval(samples)
    time_start = samples[0].time_sec
    time_end = samples[-1].time_sec + dt
    times = [sample.time_sec for sample in samples]

    col_width = 420.0
    row_heights = (220.0, 180.0, 72.0)
    left_margin = 70.0
    top_margin = 70.0
    row_gap = 54.0
    col_gap = 36.0
    width = left_margin + len(cpus) * col_width + max(0, len(cpus) - 1) * col_gap + 30.0
    height = top_margin + sum(row_heights) + 2 * row_gap + 70.0

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        f'<text x="{width * 0.5:.1f}" y="28" text-anchor="middle" font-size="20" '
        'font-weight="700" fill="#0f172a">'
        f'{escape("Scheduler debug analysis: " + path.name)}</text>',
    ]

    render_svg_metric_legend(
        parts,
        [
            ("policy(time_in_state)", METRIC_COLORS["policy"], None),
            ("scaling_cur_freq", METRIC_COLORS["scaling"], "8 4"),
            ("cpuinfo_avg_freq", METRIC_COLORS["avg"], "2 3"),
            ("planned target MHz", METRIC_COLORS["target"], None),
        ],
        left_margin,
        48.0,
    )
    render_svg_status_legend(parts, left_margin, height - 18.0)

    for col, cpu in enumerate(cpus):
        panel_x = left_margin + col * (col_width + col_gap)

        freq_y = top_margin
        target_y = freq_y + row_heights[0] + row_gap
        status_y = target_y + row_heights[1] + row_gap

        policy_vals = []
        scaling_vals = []
        avg_vals = []
        target_vals = []
        statuses = []
        labels_to_draw: list[tuple[float, float, str, str]] = []
        prev_status: str | None = None

        for sample in samples:
            state = sample.cpus.get(cpu, CpuSample())
            policy_vals.append(state.policy_mhz)
            scaling_vals.append(state.scaling_mhz)
            avg_vals.append(state.avg_mhz)
            target_vals.append(state.target_mhz if state.target_mhz > 0.0 else math.nan)

            status = classify_sample(state)
            statuses.append(status)

            if status != prev_status:
                text = event_annotation_text(state, status)
                if text:
                    labels_to_draw.append((sample.time_sec, state.target_mhz, text, status))
            prev_status = status

        render_svg_axes(parts, panel_x, freq_y, col_width, row_heights[0],
                        time_start, time_end, y_min, y_max,
                        f"CPU {cpu}: observed", "Observed MHz")
        render_svg_series(parts, times, policy_vals,
                          x0=panel_x, y0=freq_y, width=col_width, height=row_heights[0],
                          t_min=time_start, t_max=time_end, v_min=y_min, v_max=y_max,
                          color=METRIC_COLORS["policy"], stroke_width=2.1)
        render_svg_series(parts, times, scaling_vals,
                          x0=panel_x, y0=freq_y, width=col_width, height=row_heights[0],
                          t_min=time_start, t_max=time_end, v_min=y_min, v_max=y_max,
                          color=METRIC_COLORS["scaling"], stroke_width=1.9, dasharray="8 4")
        render_svg_series(parts, times, avg_vals,
                          x0=panel_x, y0=freq_y, width=col_width, height=row_heights[0],
                          t_min=time_start, t_max=time_end, v_min=y_min, v_max=y_max,
                          color=METRIC_COLORS["avg"], stroke_width=1.8, dasharray="2 3")

        render_svg_axes(parts, panel_x, target_y, col_width, row_heights[1],
                        time_start, time_end, y_min, y_max,
                        f"CPU {cpu}: target + events", "Target MHz")
        render_svg_series(parts, times, target_vals,
                          x0=panel_x, y0=target_y, width=col_width, height=row_heights[1],
                          t_min=time_start, t_max=time_end, v_min=y_min, v_max=y_max,
                          color=METRIC_COLORS["target"], stroke_width=2.2)
        for t, target_mhz, label, status in labels_to_draw:
            y = target_mhz if target_mhz > 0.0 else y_min + (y_max - y_min) * 0.1
            cx = svg_x(t, panel_x, col_width, time_start, time_end)
            cy = svg_y(y, target_y, row_heights[1], y_min, y_max)
            parts.append(
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="3.5" fill="{STATUS_COLORS[status]}"/>'
            )
            parts.append(
                f'<text x="{cx:.1f}" y="{cy - 8:.1f}" text-anchor="middle" font-size="10" '
                f'fill="{STATUS_COLORS[status]}">{escape(label)}</text>'
            )

        render_svg_axes(parts, panel_x, status_y, col_width, row_heights[2],
                        time_start, time_end, 0.0, 1.0,
                        f"CPU {cpu}: state ribbon", "State")
        for idx, status in enumerate(statuses):
            start = times[idx]
            end = times[idx + 1] if idx + 1 < len(times) else start + dt
            x1 = svg_x(start, panel_x, col_width, time_start, time_end)
            x2 = svg_x(end, panel_x, col_width, time_start, time_end)
            parts.append(
                f'<rect x="{x1:.1f}" y="{status_y:.1f}" width="{max(1.0, x2 - x1):.1f}" '
                f'height="{row_heights[2]:.1f}" fill="{STATUS_COLORS[status]}" opacity="0.88"/>'
            )

    parts.append("</svg>")
    return write_svg(svg_output_path(path), "\n".join(parts))


def plot_dbg_log(path: Path) -> None:
    cpus, samples = parse_log(path)
    try:
        import matplotlib.pyplot as plt
        from matplotlib.patches import Patch
    except ModuleNotFoundError:
        output_path = render_svg_fallback(path, cpus, samples)
        print(f"matplotlib is not installed, SVG graph saved to {output_path}")
        return

    y_min, y_max = value_limits(samples, cpus)
    dt = sample_interval(samples)
    time_start = samples[0].time_sec
    time_end = samples[-1].time_sec
    times = [sample.time_sec for sample in samples]

    nrows = 3
    ncols = len(cpus)
    fig_width = max(6.5, 5.1 * ncols)
    fig_height = 9.5
    fig, axes = plt.subplots(
        nrows,
        ncols,
        figsize=(fig_width, fig_height),
        sharex=True,
        squeeze=False,
        gridspec_kw={"height_ratios": [2.4, 2.0, 0.9]},
    )

    legend_handles = [
        Patch(facecolor=color, edgecolor=color, label=STATUS_LABELS[key])
        for key, color in STATUS_COLORS.items()
    ]

    for col, cpu in enumerate(cpus):
        ax_freq = axes[0][col]
        ax_target = axes[1][col]
        ax_status = axes[2][col]

        policy_vals = []
        scaling_vals = []
        avg_vals = []
        target_vals = []
        statuses = []
        labels_to_draw: list[tuple[float, float, str, str]] = []
        prev_status: str | None = None

        for sample in samples:
            state = sample.cpus.get(cpu, CpuSample())
            policy_vals.append(state.policy_mhz)
            scaling_vals.append(state.scaling_mhz)
            avg_vals.append(state.avg_mhz)
            target_vals.append(state.target_mhz if state.target_mhz > 0.0 else math.nan)

            status = classify_sample(state)
            statuses.append(status)

            if status != prev_status:
                text = event_annotation_text(state, status)
                if text:
                    labels_to_draw.append((sample.time_sec, state.target_mhz, text, status))
            prev_status = status

        ax_freq.step(times, policy_vals, where="post", color=METRIC_COLORS["policy"],
                     linewidth=2.0, label="policy(time_in_state)")
        ax_freq.step(times, scaling_vals, where="post", color=METRIC_COLORS["scaling"],
                     linewidth=1.9, linestyle="--", label="scaling_cur_freq")
        ax_freq.step(times, avg_vals, where="post", color=METRIC_COLORS["avg"],
                     linewidth=1.8, linestyle=":", label="cpuinfo_avg_freq")
        ax_freq.set_ylim(y_min, y_max)
        ax_freq.grid(True, linestyle="--", alpha=0.45)
        ax_freq.set_title(f"CPU {cpu}")
        ax_freq.set_ylabel("Observed MHz")
        ax_freq.legend(loc="upper right", fontsize=8)

        ax_target.step(times, target_vals, where="post", color=METRIC_COLORS["target"],
                       linewidth=2.2, label="planned target MHz")
        for t, target_mhz, label, status in labels_to_draw:
            y = target_mhz if target_mhz > 0.0 else y_min + (y_max - y_min) * 0.1
            ax_target.scatter([t], [y], color=STATUS_COLORS[status], s=28, zorder=4)
            ax_target.text(
                t,
                y + max((y_max - y_min) * 0.025, 30.0),
                label,
                fontsize=7,
                color=STATUS_COLORS[status],
                ha="center",
                va="bottom",
                rotation=20,
            )
        ax_target.set_ylim(y_min, y_max)
        ax_target.grid(True, linestyle="--", alpha=0.45)
        ax_target.set_ylabel("Target MHz")
        ax_target.legend(loc="upper right", fontsize=8)

        ax_status.set_ylim(0.0, 1.0)
        ax_status.set_yticks([])
        ax_status.set_ylabel("State")
        ax_status.grid(False)

        for idx, status in enumerate(statuses):
            start = times[idx]
            if idx + 1 < len(times):
                end = times[idx + 1]
            else:
                end = start + dt

            ax_status.axvspan(start, end, color=STATUS_COLORS[status], alpha=0.88)

        ax_status.set_xlim(time_start, time_end + dt)
        ax_status.set_xlabel("Time (s)")

    fig.suptitle(f"Scheduler debug analysis: {path.name}")
    fig.legend(
        handles=legend_handles,
        loc="upper center",
        ncol=min(len(legend_handles), 3),
        fontsize=9,
        bbox_to_anchor=(0.5, 0.98),
    )
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.93))

    output_path = path.with_suffix(".analysis.svg")
    fig.savefig(output_path)

    backend = plt.get_backend().lower()
    if "agg" in backend:
        print(f"Saved analysis SVG to {output_path}")
    else:
        plt.show()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plot scheduler debug analysis from dbg.log."
    )
    parser.add_argument("log_path", help="Path to results/<scheduler>/dbg.log")
    args = parser.parse_args()

    path = Path(args.log_path)
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        return 1

    try:
        plot_dbg_log(path)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
