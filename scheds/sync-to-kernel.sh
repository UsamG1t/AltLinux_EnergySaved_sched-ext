#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: sync-to-kernel.sh KERNEL_TREE_TO_SYNC_TO" 1>&2
    exit 1
fi

headers=($(
    git ls-files scheds/include |
    grep -v scheds/include/lib |
    grep -v scheds/include/vmlinux |
    grep -v scheds/include/arch |
    grep -v '\.gitignore$'
))

sched_dirs=(
    scheds/scx_stairs
    scheds/scx_erf
    scheds/scx_scheduler
)

scheds=()
for sched_dir in ${sched_dirs[@]}; do
    scheds+=($(git ls-files "${sched_dir}"))
done

kernel="$1/tools/sched_ext"

echo "Syncing ${#headers[@]} headers and ${#scheds[@]} scheduler source files to $kernel"

srcs=("${headers[@]}" "${scheds[@]}")
dsts=()

# Header paths are the same relative to the base directories.
for file in ${headers[@]}; do
    dsts+=("$kernel/${file#scheds/}")
done

# Scheduler files should drop the first two directory components. ie.
# scheds/scx_erf/scx_erf.bpf.c should be synced to
# $kernel/scx_erf/scx_erf.bpf.c.
for file in ${scheds[@]}; do
    dsts+=("$kernel/${file#scheds/}")
done

## debug
# for ((i=0;i<${#srcs[@]};i++)); do
#    echo "${srcs[i]} -> ${dsts[i]}"
# done

nr_missing=0
nr_skipped=0
nr_synced=0
for ((i=0;i<${#srcs[@]};i++)); do
    src="${srcs[i]}"
    dst="${dsts[i]}"
    orig="$src"

    if [ ! -f "$dst" ]; then
        echo "WARNING: $dst does not exist" 1>&2
        nr_missing=$((nr_missing+1))
        continue
    fi

    if cmp -s "$src" "$dst"; then
        nr_skipped=$((nr_skipped+1))
        continue
    fi

    echo "Syncing $orig"

    mkdir -p "$(dirname "$dst")"
    cp -f "$src" "$dst"
    nr_synced=$((nr_synced+1))
done

echo
echo "Synced $nr_synced updated files"
echo "Skipped $nr_skipped unchanged and created $nr_missing new files"
