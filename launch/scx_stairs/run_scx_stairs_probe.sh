#!/bin/bash
set -euo pipefail

REPO="${REPO:-$PWD}"
TASK_DIR="${TASK_DIR:-${REPO}/build/scx_stairs/probe_tasks}"
SCHED="${REPO}/build/scx_stairs/scx_stairs"
ORIGIN_BIN="${REPO}/build/common/task_workload_origin"

TASKS=(
    var_7_7_1
    var_7_7_2
    var_7_7_3
    var_7_7_4
    var_7_7_5
    var_7_7_6
    var_7_7_7
    var_7_7_8
    var_7_7_9
)

SAMPLE_SEC="${SAMPLE_SEC:-0.1}"
RUN_SEC="${RUN_SEC:-10}"
IDLE_SEC="${IDLE_SEC:-2}"

OUT="${REPO}/results/scx_stairs/probe_$(date +%F_%H%M%S)"
LOG="${OUT}/driver.log"
REPORT="${OUT}/report.txt"
MARKERS="${OUT}/markers.log"

mkdir -p "${OUT}"

log() {
    echo "[$(date --iso-8601=ns)] $*" | tee -a "${LOG}"
}

find_task_cmd() {
    local name="$1"

    if [[ -x "${TASK_DIR}/${name}" ]]; then
        echo "${TASK_DIR}/${name}"
        return 0
    fi

    if command -v "${name}" >/dev/null 2>&1; then
        command -v "${name}"
        return 0
    fi

    return 1
}

rel_ms() {
    local now_ns
    now_ns=$(date +%s%N)
    echo $(( (now_ns - sched_start_ns) / 1000000 ))
}

reset_stats() {
    local c
    for c in 6 7 8 9; do
        echo 1 > "/sys/devices/system/cpu/cpufreq/policy${c}/stats/reset"
    done
}

snapshot_policy() {
    local tag="$1"
    local c
    local p

    {
        echo
        echo "===== ${tag} ====="
        echo "rel_ms=$(rel_ms)"
        echo "date=$(date --iso-8601=ns)"
        for c in 6 7 8 9; do
            p="/sys/devices/system/cpu/cpufreq/policy${c}"
            echo "--- cpu${c}"
            echo "governor=$(cat "${p}/scaling_governor")"
            echo "driver=$(cat "${p}/scaling_driver")"
            echo "min=$(cat "${p}/scaling_min_freq")"
            echo "max=$(cat "${p}/scaling_max_freq")"
            echo "bios_limit=$(cat "${p}/bios_limit" 2>/dev/null || echo -)"
            echo "boost=$(cat "${p}/boost" 2>/dev/null || echo -)"
            echo "scaling_cur_freq=$(cat "${p}/scaling_cur_freq" 2>/dev/null || echo -)"
            echo "cpuinfo_avg_freq=$(cat "${p}/cpuinfo_avg_freq" 2>/dev/null || echo -)"
            echo "time_in_state:"
            cat "${p}/stats/time_in_state"
        done
    } >> "${REPORT}"
}

cleanup() {
    set +e

    if [[ -n "${sched_pid:-}" ]] && kill -0 "${sched_pid}" 2>/dev/null; then
        log "Stopping scx_stairs pid=${sched_pid}"
        kill -INT "${sched_pid}" 2>/dev/null || true
        wait "${sched_pid}" || true
    fi

    cp "${REPO}/results/scx_stairs/latest.csv" "${OUT}/latest.csv" 2>/dev/null || true
    cp "${REPO}/results/scx_stairs/latest.meta" "${OUT}/latest.meta" 2>/dev/null || true

    log "Artifacts saved in ${OUT}"
    log "Main files: ${REPORT} ${MARKERS} ${OUT}/latest.csv ${OUT}/scheduler.stdout ${OUT}/scheduler.stderr"
}
trap cleanup EXIT

if [[ ! -x "${SCHED}" ]]; then
    echo "Scheduler not found or not executable: ${SCHED}" >&2
    exit 1
fi

: > "${LOG}"
: > "${REPORT}"
: > "${MARKERS}"

log "REPO=${REPO}"
log "TASK_DIR=${TASK_DIR}"
log "ORIGIN_BIN=${ORIGIN_BIN}"
log "SAMPLE_SEC=${SAMPLE_SEC} RUN_SEC=${RUN_SEC} IDLE_SEC=${IDLE_SEC}"
log "TASKS=${TASKS[*]}"
log "Scheduler binary: ${SCHED}"

if [[ ! -x "${ORIGIN_BIN}" ]]; then
    echo "Origin binary not found or not executable: ${ORIGIN_BIN}" >&2
    exit 1
fi

mkdir -p "${TASK_DIR}"
for task in "${TASKS[@]}"; do
    ln -sf "${ORIGIN_BIN}" "${TASK_DIR}/${task}"
done

for task in "${TASKS[@]}"; do
    if ! find_task_cmd "${task}" >/dev/null; then
        echo "Task not found: ${task}" >&2
        exit 1
    fi
done

rm -f "${REPO}/results/scx_stairs/latest.csv" "${REPO}/results/scx_stairs/latest.meta"

sched_start_ns=$(date +%s%N)
log "Starting scheduler"
"${SCHED}" -f "${SAMPLE_SEC}" > "${OUT}/scheduler.stdout" 2> "${OUT}/scheduler.stderr" &
sched_pid=$!

sleep 3

if ! kill -0 "${sched_pid}" 2>/dev/null; then
    echo "scx_stairs exited too early" >&2
    cat "${OUT}/scheduler.stderr" >&2 || true
    exit 1
fi

snapshot_policy "idle_after_scheduler_start"

run_case() {
    local name="$1"
    local cmd
    local start_ns
    local end_ns
    local rc
    local dur_ms

    cmd=$(find_task_cmd "${name}")

    log "Preparing ${name}"
    reset_stats
    snapshot_policy "before_${name}"

    sleep "${IDLE_SEC}"

    start_ns=$(date +%s%N)
    echo "START ${name} rel_ms=$(( (start_ns - sched_start_ns) / 1000000 )) date=$(date --iso-8601=ns)" >> "${MARKERS}"

    set +e
    timeout --preserve-status "${RUN_SEC}s" "${cmd}" > "${OUT}/${name}.stdout" 2> "${OUT}/${name}.stderr"
    rc=$?
    set -e

    end_ns=$(date +%s%N)
    dur_ms=$(( (end_ns - start_ns) / 1000000 ))

    echo "END ${name} rel_ms=$(( (end_ns - sched_start_ns) / 1000000 )) rc=${rc} dur_ms=${dur_ms} date=$(date --iso-8601=ns)" >> "${MARKERS}"
    snapshot_policy "after_${name}_rc_${rc}_dur_${dur_ms}ms"

    sleep "${IDLE_SEC}"
}

for task in "${TASKS[@]}"; do
    run_case "${task}"
done

snapshot_policy "final_idle"
log "Probe completed"
