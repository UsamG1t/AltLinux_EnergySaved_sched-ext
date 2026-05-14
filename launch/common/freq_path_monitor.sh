#!/usr/bin/env bash
# Monitor scheduler -> CPUFreq -> driver frequency request path.
# Intended for schedutil / CPUFreq experiments with SCX/eBPF schedulers.
#
# Output files:
#   raw_trace.txt       - original ftrace output
#   events.csv          - parsed kprobe/tracepoint events
#   sysfs_samples.csv   - periodic sysfs + MSR samples for one CPU
#   summary.txt         - compact summary and policy snapshots
#
# Usage:
#   sudo ./freq_path_monitor.sh -c 2 -d 20 -o /tmp/freqmon-cpu2
#
# Start your eBPF scheduler before the script, or start it in another terminal
# immediately after the script begins recording.

set -euo pipefail

CPU=2
DURATION=20
OUTDIR=""
SAMPLE_INTERVAL="0.2"
TRACE_BUFFER_KB=65536

usage() {
    cat <<USAGE
Usage: $0 [-c CPU] [-d SECONDS] [-o OUTDIR] [-i SAMPLE_INTERVAL]

Options:
  -c CPU              CPU to monitor for sysfs/MSR samples, default: 2
  -d SECONDS          recording duration, default: 20
  -o OUTDIR           output directory, default: /tmp/freqmon-<timestamp>
  -i SECONDS          sysfs/MSR sample interval, default: 0.2

Example:
  sudo $0 -c 2 -d 30 -o /tmp/freqmon-cpu2
USAGE
}

while getopts ":c:d:o:i:h" opt; do
    case "$opt" in
        c) CPU="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        i) SAMPLE_INTERVAL="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi

TRACEFS="/sys/kernel/tracing"
if [[ ! -d "$TRACEFS" ]]; then
    TRACEFS="/sys/kernel/debug/tracing"
fi
if [[ ! -d "$TRACEFS" ]]; then
    echo "ERROR: tracefs not found" >&2
    exit 1
fi

if [[ -z "$OUTDIR" ]]; then
    OUTDIR="/tmp/freqmon-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUTDIR"
RAW_TRACE="$OUTDIR/raw_trace.txt"
EVENTS_CSV="$OUTDIR/events.csv"
SAMPLES_CSV="$OUTDIR/sysfs_samples.csv"
SUMMARY="$OUTDIR/summary.txt"

POLICY=""
if [[ -e "/sys/devices/system/cpu/cpu${CPU}/cpufreq" ]]; then
    POLICY="$(readlink -f "/sys/devices/system/cpu/cpu${CPU}/cpufreq" || true)"
fi

# Names of probes created by this script.
PROBES=(
    "getnext_in" "getnext_out"
    "resolve_in" "resolve_out"
    "fast_in" "fast_out"
    "target_in" "target_out"
)

cleanup() {
    set +e
    echo 0 > "$TRACEFS/tracing_on" 2>/dev/null
    if [[ -d "$TRACEFS/events/freqmon" ]]; then
        echo 0 > "$TRACEFS/events/freqmon/enable" 2>/dev/null
    fi
    # Delete only our probes. Ignore errors because missing probes are harmless.
    for p in "${PROBES[@]}"; do
        echo "-:freqmon/$p" >> "$TRACEFS/kprobe_events" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM

have_symbol() {
    local sym="$1"
    grep -qw "$sym" /proc/kallsyms
}

add_probe() {
    local spec="$1"
    echo "$spec" >> "$TRACEFS/kprobe_events" 2>/dev/null || {
        echo "WARN: failed to add kprobe: $spec" | tee -a "$SUMMARY" >&2
        return 1
    }
}

write_policy_snapshot() {
    local title="$1"
    {
        echo "=== $title ==="
        echo "timestamp: $(date --iso-8601=ns)"
        echo "cpu: $CPU"
        echo "tracefs: $TRACEFS"
        echo "cmdline: $(cat /proc/cmdline)"
        echo
        echo "--- CPUFreq policy for CPU $CPU ---"
        if [[ -n "$POLICY" && -d "$POLICY" ]]; then
            echo "policy_path: $POLICY"
            for f in affected_cpus related_cpus scaling_driver scaling_governor \
                     scaling_min_freq scaling_max_freq cpuinfo_min_freq cpuinfo_max_freq \
                     scaling_cur_freq cpuinfo_cur_freq cpuinfo_avg_freq bios_limit \
                     scaling_available_frequencies; do
                [[ -e "$POLICY/$f" ]] && printf '%-36s %s\n' "$f:" "$(cat "$POLICY/$f")"
            done
        else
            echo "NO CPUFreq policy for CPU $CPU"
        fi
        echo
    } >> "$SUMMARY"
}

sample_loop() {
    local end_ts
    end_ts=$(awk -v d="$DURATION" 'BEGIN { printf "%.6f", systime() + d }')
    echo "time_ns,cpu,scaling_cur_freq,cpuinfo_avg_freq,perf_ctl_hex,perf_ctl_ratio,perf_ctl_mhz,perf_status_hex,perf_status_ratio,perf_status_mhz" > "$SAMPLES_CSV"

    modprobe msr 2>/dev/null || true

    while awk -v now="$(date +%s)" -v end="$end_ts" 'BEGIN { exit !(now < end) }'; do
        local t scur avg ctl stat ctl_ratio stat_ratio ctl_mhz stat_mhz
        t="$(date +%s%N)"
        scur=""
        avg=""
        ctl=""
        stat=""
        ctl_ratio=""
        stat_ratio=""
        ctl_mhz=""
        stat_mhz=""

        if [[ -n "$POLICY" && -d "$POLICY" ]]; then
            [[ -e "$POLICY/scaling_cur_freq" ]] && scur="$(cat "$POLICY/scaling_cur_freq" 2>/dev/null || true)"
            [[ -e "$POLICY/cpuinfo_avg_freq" ]] && avg="$(cat "$POLICY/cpuinfo_avg_freq" 2>/dev/null || true)"
        fi

        if command -v rdmsr >/dev/null 2>&1; then
            ctl="$(rdmsr -p "$CPU" 0x199 2>/dev/null || true)"
            stat="$(rdmsr -p "$CPU" 0x198 2>/dev/null || true)"
            if [[ -n "$ctl" ]]; then
                ctl_ratio=$(( (16#$ctl >> 8) & 255 ))
                ctl_mhz=$(( ctl_ratio * 100 ))
            fi
            if [[ -n "$stat" ]]; then
                stat_ratio=$(( (16#$stat >> 8) & 255 ))
                stat_mhz=$(( stat_ratio * 100 ))
            fi
        fi

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$t" "$CPU" "$scur" "$avg" "$ctl" "$ctl_ratio" "$ctl_mhz" "$stat" "$stat_ratio" "$stat_mhz" >> "$SAMPLES_CSV"
        sleep "$SAMPLE_INTERVAL"
    done
}

cd "$TRACEFS"
cleanup
: > "$SUMMARY"
write_policy_snapshot "BEFORE RECORDING"

# Increase buffer if possible. Ignore failures on restricted systems.
echo "$TRACE_BUFFER_KB" > "$TRACEFS/buffer_size_kb" 2>/dev/null || true
: > "$TRACEFS/trace"
: > "$TRACEFS/set_event" 2>/dev/null || true
: > "$TRACEFS/kprobe_events" 2>/dev/null || true

# schedutil decision point. get_next_freq() returns cached/resolved next freq.
if have_symbol get_next_freq; then
    add_probe 'p:freqmon/getnext_in get_next_freq sg_policy=$arg1 util=$arg2 max=$arg3' || true
    add_probe 'r:freqmon/getnext_out get_next_freq ret=$retval' || true
fi

# Input from schedutil into CPUFreq resolver, and resolved output from CPUFreq.
if have_symbol cpufreq_driver_resolve_freq; then
    add_probe 'p:freqmon/resolve_in cpufreq_driver_resolve_freq policy=$arg1 target=$arg2' || true
    add_probe 'r:freqmon/resolve_out cpufreq_driver_resolve_freq ret=$retval' || true
fi

# Fast-switch driver input and output. For intel_cpufreq passive mode this is usually the decisive path.
if have_symbol cpufreq_driver_fast_switch; then
    add_probe 'p:freqmon/fast_in cpufreq_driver_fast_switch policy=$arg1 target=$arg2' || true
    add_probe 'r:freqmon/fast_out cpufreq_driver_fast_switch ret=$retval' || true
fi

# Slow path driver request. Return value is status, not output frequency.
if have_symbol __cpufreq_driver_target; then
    add_probe 'p:freqmon/target_in __cpufreq_driver_target policy=$arg1 target=$arg2 relation=$arg3' || true
    add_probe 'r:freqmon/target_out __cpufreq_driver_target ret=$retval' || true
fi

# Static tracepoints, when available.
[[ -e "$TRACEFS/events/power/cpu_frequency/enable" ]] && echo 1 > "$TRACEFS/events/power/cpu_frequency/enable" || true
[[ -e "$TRACEFS/events/power/cpu_frequency_limits/enable" ]] && echo 1 > "$TRACEFS/events/power/cpu_frequency_limits/enable" || true

if [[ -d "$TRACEFS/events/freqmon" ]]; then
    echo 1 > "$TRACEFS/events/freqmon/enable"
else
    echo "ERROR: no freqmon kprobe group was created. Check /proc/kallsyms and kprobe availability." >&2
    exit 1
fi

sample_loop &
SAMPLE_PID=$!

echo "Recording for ${DURATION}s..."
echo "Output directory: $OUTDIR"
echo "Start/keep your scheduler and workload running now if not already active."

echo 1 > "$TRACEFS/tracing_on"
sleep "$DURATION"
echo 0 > "$TRACEFS/tracing_on"

wait "$SAMPLE_PID" 2>/dev/null || true
cat "$TRACEFS/trace" > "$RAW_TRACE"
write_policy_snapshot "AFTER RECORDING"

# Parse raw trace into CSV and append summary.
python3 - "$RAW_TRACE" "$EVENTS_CSV" "$SUMMARY" <<'PY'
import csv
import re
import sys
from collections import Counter, defaultdict

raw_path, csv_path, summary_path = sys.argv[1:4]

line_re = re.compile(r'^\s*(?P<comm>.+?)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\].*?\s(?P<ts>\d+\.\d+):\s+(?P<event>[\w/]+):\s+(?P<rest>.*)$')
kv_re = re.compile(r'(\w+)=([^\s]+)')

def to_int(s):
    if s is None or s == '':
        return ''
    try:
        if s.startswith('0x'):
            return str(int(s, 16))
        return str(int(s, 10))
    except Exception:
        return s

rows = []
counts = Counter()
values = defaultdict(Counter)

with open(raw_path, 'r', errors='replace') as f:
    for line in f:
        m = line_re.match(line)
        if not m:
            continue
        event = m.group('event').split('/')[-1]
        rest = m.group('rest')
        kv = dict(kv_re.findall(rest))
        row = {
            'timestamp': m.group('ts'),
            'trace_cpu': m.group('cpu'),
            'comm': m.group('comm').strip(),
            'pid': m.group('pid'),
            'event': event,
            'policy': kv.get('policy', ''),
            'target_khz': to_int(kv.get('target', '')),
            'ret': to_int(kv.get('ret', '')),
            'state_khz': to_int(kv.get('state', '')),
            'cpu_id': to_int(kv.get('cpu_id', '')),
            'min_khz': to_int(kv.get('min', '')),
            'max_khz': to_int(kv.get('max', '')),
            'util': to_int(kv.get('util', '')),
            'max_capacity': to_int(kv.get('max', '')) if event in ('getnext_in',) else '',
            'raw': line.rstrip('\n'),
        }
        rows.append(row)
        counts[event] += 1
        for key in ('target_khz', 'ret', 'state_khz', 'cpu_id', 'min_khz', 'max_khz'):
            if row[key] != '':
                values[(event, key)][row[key]] += 1

fields = ['timestamp','trace_cpu','comm','pid','event','policy','target_khz','ret','state_khz','cpu_id','min_khz','max_khz','util','max_capacity','raw']
with open(csv_path, 'w', newline='') as out:
    w = csv.DictWriter(out, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

with open(summary_path, 'a') as s:
    s.write('\n=== TRACE SUMMARY ===\n')
    s.write(f'parsed_events: {len(rows)}\n')
    for event, count in counts.most_common():
        s.write(f'{event}: {count}\n')
    s.write('\n=== DISTINCT VALUES ===\n')
    for (event, key), ctr in sorted(values.items()):
        top = ', '.join(f'{v}({c})' for v, c in ctr.most_common(20))
        s.write(f'{event}.{key}: {top}\n')
PY

{
    echo
    echo "=== FILES ==="
    echo "raw_trace:       $RAW_TRACE"
    echo "events_csv:      $EVENTS_CSV"
    echo "sysfs_samples:   $SAMPLES_CSV"
    echo "summary:         $SUMMARY"
    echo
    echo "=== SHORT SUMMARY ==="
    grep -A200 '^=== TRACE SUMMARY ===' "$SUMMARY" || true
} | tee -a "$SUMMARY"

