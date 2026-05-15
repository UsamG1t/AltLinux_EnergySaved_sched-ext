#!/usr/bin/env python3

import argparse
import sys

SCX_CPUPERF_ONE = 1024


def parse_freq(value: str) -> int:
    cleaned = value.replace("_", "").replace(",", "").strip()
    try:
        freq = int(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid frequency '{value}'") from exc
    if freq <= 0:
        raise argparse.ArgumentTypeError("frequency must be positive")
    return freq


def build_steps(cpuinfo_max_khz: int, freqs_khz: list[int]) -> list[tuple[int, int, int]]:
    steps = []
    for idx, freq_khz in enumerate(freqs_khz, start=1):
        perf_target = round(SCX_CPUPERF_ONE * freq_khz / cpuinfo_max_khz)
        steps.append((idx, freq_khz, perf_target))
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calculate initial SCX perf_target values from frequency steps.",
    )
    parser.add_argument(
        "--cpuinfo-max-khz",
        "--max-freq-khz",
        dest="cpuinfo_max_khz",
        type=parse_freq,
        required=True,
        help="cpuinfo_max_freq in kHz used in perf_target ~= round(1024 * freq / cpuinfo_max_freq)",
    )
    parser.add_argument(
        "freqs_khz",
        nargs="+",
        type=parse_freq,
        help="available frequencies in kHz",
    )
    args = parser.parse_args()

    freqs_khz = sorted(dict.fromkeys(args.freqs_khz))
    min_freq_khz = min(freqs_khz)
    max_freq_khz = max(freqs_khz)
    steps = build_steps(args.cpuinfo_max_khz, freqs_khz)

    print(f"# cpuinfo_max_freq = {args.cpuinfo_max_khz:_d} kHz", file=sys.stderr)
    print(f"# available range   = {min_freq_khz:_d} .. {max_freq_khz:_d} kHz", file=sys.stderr)
    print("MAX_FREQ_KHZ = {:_d}".format(max_freq_khz))
    print("MIN_FREQ_KHZ = {:_d}".format(min_freq_khz))
    print("ERF_SLACK_PCT = 0")
    print("FREQ_STEPS = [")
    for idx, freq_khz, perf_target in steps:
        print(f"    ({idx}, {freq_khz:_d}, {perf_target}),")
    print("]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
