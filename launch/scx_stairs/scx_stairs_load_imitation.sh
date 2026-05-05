#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
    echo "Использование: $0 <file_with_task_names> <l_task_seconds> <m_pause_seconds>" >&2
    exit 1
fi

TASK_FILE="$1"
TASK_DURATION="$2"
PAUSE_DURATION="$3"

REPO="${REPO:-$PWD}"
SCHED="${REPO}/build/scx_stairs/scx_stairs"
ORIGIN_BIN="${REPO}/build/common/task_workload_origin"
RUN_DIR="${REPO}/build/scx_stairs/imitation"

SCHED_PID=""
TASK_PID=""
SLEEP_PID=""
CURRENT_LINK=""
CLEANUP_DONE=0

usage_error() {
    echo "Ошибка: $1" >&2
    exit 1
}

is_nonnegative_int() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

stop_group() {
    local pid="$1"
    local grace="${2:-2}"

    [[ -n "$pid" ]] || return 0
    kill -0 "$pid" 2>/dev/null || return 0

    # Сначала мягкое завершение всей process group
    kill -TERM -- "-$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true

    local i
    for ((i = 0; i < grace * 10; i++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done

    # Если не завершилось — добиваем
    kill -KILL -- "-$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    if [[ "$CLEANUP_DONE" -eq 1 ]]; then
        return 0
    fi
    CLEANUP_DONE=1

    # Остановить sleep, если он идёт
    if [[ -n "${SLEEP_PID:-}" ]]; then
        kill "$SLEEP_PID" 2>/dev/null || true
        wait "$SLEEP_PID" 2>/dev/null || true
        SLEEP_PID=""
    fi

    # Остановить текущую задачу
    if [[ -n "${TASK_PID:-}" ]]; then
        stop_group "$TASK_PID" 2
        TASK_PID=""
    fi

    # Удалить текущую ссылку
    if [[ -n "${CURRENT_LINK:-}" ]]; then
        rm -f -- "$CURRENT_LINK" 2>/dev/null || true
        CURRENT_LINK=""
    fi

    # Остановить планировщик
    if [[ -n "${SCHED_PID:-}" ]]; then
        stop_group "$SCHED_PID" 2
        SCHED_PID=""
    fi
}

on_interrupt() {
    cleanup
    exit 130
}

on_term() {
    cleanup
    exit 143
}

trap on_interrupt INT
trap on_term TERM
trap cleanup EXIT

[[ -f "$TASK_FILE" ]] || usage_error "файл '$TASK_FILE' не найден"
[[ -x "$SCHED" ]] || usage_error "планировщик '$SCHED' не найден или не исполняемый"
[[ -x "$ORIGIN_BIN" ]] || usage_error "файл '$ORIGIN_BIN' не найден или не исполняемый"

is_nonnegative_int "$TASK_DURATION" || usage_error "длительность задачи должна быть неотрицательным целым числом"
is_nonnegative_int "$PAUSE_DURATION" || usage_error "длительность паузы должна быть неотрицательным целым числом"

mkdir -p -- "$RUN_DIR"

# Добавляем каталог с имитационными именами в PATH
export PATH="$RUN_DIR:$PATH"
hash -r

# Читаем список имён задач
TASK_NAMES=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    TASK_NAMES+=("$line")
done < "$TASK_FILE"

[[ "${#TASK_NAMES[@]}" -gt 0 ]] || usage_error "файл '$TASK_FILE' не содержит имён задач"

echo "Запуск планировщика: $SCHED"
setsid "$SCHED" &
SCHED_PID=$!

# Небольшая пауза, чтобы планировщик успел инициализироваться
sleep 1

if ! kill -0 "$SCHED_PID" 2>/dev/null; then
    usage_error "планировщик завершился сразу после запуска"
fi

sleep_interruptible() {
    local seconds="$1"
    sleep "$seconds" &
    SLEEP_PID=$!
    wait "$SLEEP_PID"
    SLEEP_PID=""
}

idx=0
count="${#TASK_NAMES[@]}"

while true; do
    task_name="${TASK_NAMES[$idx]}"
    link_path="$RUN_DIR/$task_name"

    rm -f -- "$link_path"
    ln -s -- "$ORIGIN_BIN" "$link_path"
    CURRENT_LINK="$link_path"
    hash -r

    echo "[$(date '+%F %T')] Запуск задачи: $task_name"

    # Запускаем задачу по имени через PATH.
    # setsid создаёт отдельную process group, чтобы потом убить всю группу целиком.
    setsid bash -c 'exec "$1"' _ "$task_name" &
    TASK_PID=$!

    # Небольшая задержка, чтобы убедиться, что процесс действительно стартовал
    sleep 0.1
    if ! kill -0 "$TASK_PID" 2>/dev/null; then
        echo "[$(date '+%F %T')] Ошибка: задача '$task_name' завершилась сразу после запуска" >&2
        rm -f -- "$link_path"
        CURRENT_LINK=""
        idx=$(( (idx + 1) % count ))
        sleep_interruptible "$PAUSE_DURATION"
        continue
    fi

    sleep_interruptible "$TASK_DURATION"

    echo "[$(date '+%F %T')] Остановка задачи: $task_name"
    stop_group "$TASK_PID" 2
    TASK_PID=""

    rm -f -- "$link_path"
    CURRENT_LINK=""

    sleep_interruptible "$PAUSE_DURATION"

    idx=$(( (idx + 1) % count ))
done
