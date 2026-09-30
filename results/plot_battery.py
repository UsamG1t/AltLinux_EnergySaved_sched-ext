import argparse
import csv
import math
import sys
from dataclasses import dataclass
from html import escape
from pathlib import Path


COLORS = (
    "#0b6e4f",
    "#c2410c",
    "#1d4ed8",
    "#9333ea",
    "#be123c",
    "#0369a1",
    "#4d7c0f",
    "#a16207",
)


@dataclass(frozen=True)
class BatterySeries:
    label: str
    times_sec: list[float]
    values: list[float]


def parse_optional_float(value: str | None) -> float:
    if value is None:
        return math.nan

    text = value.strip()
    if not text or text.lower() in {"none", "nan"}:
        return math.nan
    return float(text)


def load_battery_log(path: Path, use_mah: bool) -> BatterySeries:
    times_sec: list[float] = []
    values: list[float] = []

    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames:
            raise ValueError(f"{path}: файл не содержит заголовка")

        required = {"elapsed_sec"}
        if use_mah:
            if (
                "charge_now_uah" not in reader.fieldnames
                and not {"energy_now_uwh", "voltage_now_uv"}.issubset(
                    reader.fieldnames
                )
            ):
                raise ValueError(
                    f"{path}: для --mah требуется поле charge_now_uah "
                    "или поля energy_now_uwh и voltage_now_uv"
                )
        else:
            required.add("energy_now_uwh")

        missing = required.difference(reader.fieldnames)
        if missing:
            raise ValueError(
                f"{path}: отсутствуют поля {', '.join(sorted(missing))}"
            )

        for row in reader:
            try:
                elapsed = parse_optional_float(row.get("elapsed_sec"))
                energy_uwh = parse_optional_float(row.get("energy_now_uwh"))
                if use_mah:
                    charge_uah = parse_optional_float(row.get("charge_now_uah"))
                    if math.isfinite(charge_uah):
                        value = charge_uah / 1_000.0
                    else:
                        voltage_uv = parse_optional_float(
                            row.get("voltage_now_uv")
                        )
                        if (
                            not math.isfinite(energy_uwh)
                            or not math.isfinite(voltage_uv)
                            or voltage_uv <= 0.0
                        ):
                            continue
                        value = energy_uwh / voltage_uv * 1_000.0
                else:
                    value = energy_uwh / 1_000_000.0
            except ValueError:
                continue

            if not math.isfinite(elapsed) or not math.isfinite(value):
                continue

            times_sec.append(elapsed)
            values.append(value)

    if not times_sec:
        quantity = "заряда" if use_mah else "энергии"
        raise ValueError(f"{path}: нет корректных измерений {quantity}")

    return BatterySeries(
        label=path.stem,
        times_sec=times_sec,
        values=values,
    )


def interpolate_time(
    time_before: float,
    energy_before: float,
    time_after: float,
    energy_after: float,
    target_energy: float,
) -> float:
    if math.isclose(energy_before, energy_after):
        return time_after

    fraction = (target_energy - energy_before) / (energy_after - energy_before)
    return time_before + fraction * (time_after - time_before)


def clip_series_to_energy_range(
    series: BatterySeries,
    upper_energy: float,
    lower_energy: float,
) -> BatterySeries:
    start_index = 0
    start_time = series.times_sec[0]

    above_upper = [
        index
        for index, energy_value in enumerate(series.values[:-1])
        if energy_value > upper_energy
    ]
    if above_upper:
        before_index = above_upper[-1]
        start_index = before_index + 1
        if series.values[start_index] > upper_energy:
            raise ValueError(
                f"{series.label}: верхняя граница общего диапазона недоступна"
            )
        start_time = interpolate_time(
            series.times_sec[before_index],
            series.values[before_index],
            series.times_sec[start_index],
            series.values[start_index],
            upper_energy,
        )

    end_index = len(series.values) - 1
    end_time = series.times_sec[-1]
    if series.values[-1] < lower_energy:
        for index in range(max(start_index + 1, 1), len(series.values)):
            if series.values[index] <= lower_energy:
                end_index = index
                end_time = interpolate_time(
                    series.times_sec[index - 1],
                    series.values[index - 1],
                    series.times_sec[index],
                    series.values[index],
                    lower_energy,
                )
                break

    times_sec = [0.0]
    values = [upper_energy]
    for index in range(start_index, end_index + 1):
        time_value = series.times_sec[index]
        energy_value = series.values[index]
        if time_value <= start_time or time_value >= end_time:
            continue
        if lower_energy < energy_value < upper_energy:
            times_sec.append(time_value - start_time)
            values.append(energy_value)

    if not math.isclose(upper_energy, lower_energy):
        times_sec.append(end_time - start_time)
        values.append(lower_energy)

    return BatterySeries(
        label=series.label,
        times_sec=times_sec,
        values=values,
    )


def union_series_ranges(series_list: list[BatterySeries]) -> list[BatterySeries]:
    upper_energy = min(series.values[0] for series in series_list)
    lower_energy = max(series.values[-1] for series in series_list)
    if upper_energy < lower_energy or math.isclose(upper_energy, lower_energy):
        raise ValueError("графики не имеют общего диапазона значений")

    return [
        clip_series_to_energy_range(series, upper_energy, lower_energy)
        for series in series_list
    ]


def import_pyplot():
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return None
    return plt


def expanded_limits(values: list[float], minimum_padding: float) -> tuple[float, float]:
    low = min(values)
    high = max(values)
    span = high - low
    padding = max(span * 0.06, minimum_padding)
    return low - padding, high + padding


def step_points(series: BatterySeries) -> list[tuple[float, float]]:
    points = [(series.times_sec[0], series.values[0])]
    for index in range(1, len(series.times_sec)):
        points.append((series.times_sec[index], series.values[index - 1]))
        points.append((series.times_sec[index], series.values[index]))
    return points


def format_energy_tick(value: float) -> str:
    if value >= 1.0:
        return f"{value:.3f}"
    if value >= 0.01:
        return f"{value:.4f}"
    return f"{value:.2e}"


def render_svg(
    series_list: list[BatterySeries],
    output_path: Path,
    log_scale: bool,
    use_mah: bool,
) -> None:
    width = 1200
    height = 700
    left = 105
    right = 280
    top = 55
    bottom = 85
    plot_width = width - left - right
    plot_height = height - top - bottom
    y_axis_label = (
        "Оставшийся заряд батареи (мА·ч)"
        if use_mah
        else "Оставшаяся энергия батареи (Вт·ч)"
    )

    all_times = [
        value
        for series in series_list
        for value in series.times_sec
        if not log_scale or value > 0.0
    ]
    if not all_times:
        raise ValueError("логарифмическая шкала требует положительного времени")

    all_energy = [value for series in series_list for value in series.values]
    if log_scale:
        x_min = min(all_times) * 0.85
        x_max = max(all_times) * 1.08
        log_x_min = math.log10(x_min)
        log_x_max = math.log10(x_max)
    else:
        x_min, x_max = expanded_limits(all_times, 0.5)
    y_min, y_max = expanded_limits(all_energy, 0.01)

    def x_coord(value: float) -> float:
        if log_scale:
            log_value = math.log10(value)
            return (
                left
                + (log_value - log_x_min)
                / (log_x_max - log_x_min)
                * plot_width
            )
        return left + (value - x_min) / (x_max - x_min) * plot_width

    def y_coord(value: float) -> float:
        return top + (y_max - value) / (y_max - y_min) * plot_height

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#fafaf7"/>',
        '<g font-family="DejaVu Sans, sans-serif" fill="#17211c">',
    ]

    for tick in range(6):
        fraction = tick / 5
        x = left + fraction * plot_width
        if log_scale:
            time_value = 10 ** (
                log_x_min + fraction * (log_x_max - log_x_min)
            )
        else:
            time_value = x_min + fraction * (x_max - x_min)
        lines.append(
            f'<line x1="{x:.2f}" y1="{top}" x2="{x:.2f}" '
            f'y2="{top + plot_height}" stroke="#d9dedb" stroke-width="1"/>'
        )
        lines.append(
            f'<text x="{x:.2f}" y="{top + plot_height + 28}" '
            f'text-anchor="middle" font-size="15">{time_value:.1f}</text>'
        )

    for tick in range(6):
        fraction = tick / 5
        y = top + fraction * plot_height
        energy_value = y_max - fraction * (y_max - y_min)
        lines.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + plot_width}" '
            f'y2="{y:.2f}" stroke="#d9dedb" stroke-width="1"/>'
        )
        lines.append(
            f'<text x="{left - 14}" y="{y + 5:.2f}" text-anchor="end" '
            f'font-size="15">{format_energy_tick(energy_value)}</text>'
        )

    lines.append(
        f'<line x1="{left}" y1="{top + plot_height}" '
        f'x2="{left + plot_width}" y2="{top + plot_height}" '
        'stroke="#17211c" stroke-width="1.5"/>'
    )
    lines.append(
        f'<line x1="{left}" y1="{top}" x2="{left}" '
        f'y2="{top + plot_height}" stroke="#17211c" stroke-width="1.5"/>'
    )

    for index, series in enumerate(series_list):
        color = COLORS[index % len(COLORS)]
        points = " ".join(
            f"{x_coord(x):.2f},{y_coord(y):.2f}"
            for x, y in step_points(series)
            if not log_scale or x > 0.0
        )
        lines.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" '
            'stroke-width="2.5" stroke-linejoin="round"/>'
        )

        legend_y = top + 24 + index * 29
        lines.append(
            f'<line x1="{left + plot_width + 28}" y1="{legend_y}" '
            f'x2="{left + plot_width + 66}" y2="{legend_y}" '
            f'stroke="{color}" stroke-width="3"/>'
        )
        lines.append(
            f'<text x="{left + plot_width + 76}" y="{legend_y + 5}" '
            f'font-size="16">{escape(series.label)}</text>'
        )

    lines.append(
        f'<text x="{left + plot_width / 2:.2f}" y="{height - 25}" '
        'text-anchor="middle" font-size="18">Время (с)</text>'
    )
    lines.append(
        f'<text x="28" y="{top + plot_height / 2:.2f}" text-anchor="middle" '
        'font-size="18" '
        f'transform="rotate(-90 28 {top + plot_height / 2:.2f})">'
        f"{y_axis_label}"
        "</text>"
    )
    lines.extend(["</g>", "</svg>"])

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def plot_with_matplotlib(
    series_list: list[BatterySeries],
    log_scale: bool,
    use_mah: bool,
    output_path: Path | None = None,
) -> None:
    plt = import_pyplot()
    if plt is None:
        if output_path is not None and output_path.suffix.lower() != ".svg":
            raise ValueError(
                f"matplotlib не установлен, поддерживается только вывод в .svg: {output_path}"
            )
        output_path = output_path or Path("battery_plot.svg")
        render_svg(series_list, output_path, log_scale, use_mah)
        print(f"matplotlib не установлен, график сохранён в {output_path}")
        return

    fig, ax = plt.subplots(figsize=(11.5, 6.5))
    for index, series in enumerate(series_list):
        if log_scale:
            points = [
                (time_value, energy_value)
                for time_value, energy_value in zip(
                    series.times_sec, series.values
                )
                if time_value > 0.0
            ]
            if not points:
                continue
            times_sec, energy_wh = map(list, zip(*points))
        else:
            times_sec = series.times_sec
            energy_wh = series.values

        ax.step(
            times_sec,
            energy_wh,
            where="post",
            linewidth=2.2,
            color=COLORS[index % len(COLORS)],
            label=series.label,
        )

    if log_scale:
        ax.set_xscale("log")
    ax.set_xlabel("Время (с)")
    if use_mah:
        ax.set_ylabel("Оставшийся заряд батареи (мА·ч)")
    else:
        ax.set_ylabel("Оставшаяся энергия батареи (Вт·ч)")
    ax.grid(
        True,
        which="both" if log_scale else "major",
        color="#d9dedb",
        linewidth=0.8,
        alpha=0.8,
    )
    ax.legend()
    fig.tight_layout()

    if output_path is not None:
        fig.savefig(output_path, dpi=150)
        plt.close(fig)
        print(f"График сохранён в {output_path}")
        return

    plt.show()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Построение графиков энергии батареи из логов scx_borders"
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Один или несколько файлов battery.csv",
    )
    parser.add_argument(
        "--union",
        action="store_true",
        help=(
            "Обрезать графики до общего диапазона значений и сдвинуть "
            "их начало в t=0"
        ),
    )
    parser.add_argument(
        "--log",
        action="store_true",
        help="Использовать логарифмическую шкалу времени",
    )
    parser.add_argument(
        "--mah",
        action="store_true",
        help=(
            "Показывать оставшийся заряд в мА·ч вместо энергии в Вт·ч; "
            "используется charge_now_uah или расчёт energy_now_uwh/voltage_now_uv"
        ),
    )
    parser.add_argument(
        "-o",
        dest="output_path",
        type=Path,
        help=(
            "Сохранить график в файл (.png, .svg, .pdf) вместо показа окна; "
            "без matplotlib поддерживается только .svg"
        ),
    )
    args = parser.parse_args()

    try:
        series_list = []
        for path in args.files:
            if not path.is_file():
                raise ValueError(f"{path}: файл не найден")
            series_list.append(load_battery_log(path, args.mah))
        if args.union:
            series_list = union_series_ranges(series_list)
        plot_with_matplotlib(series_list, args.log, args.mah, args.output_path)
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
