#!/usr/bin/env bash
# Run with out/bash. The loop uses Bash builtins and gpu only.
# shellcheck disable=SC2127
# Bash 5.3 supports the current-shell substitution used by layout.
set -euo pipefail
frames=${1:-0}
[[ $frames =~ ^[0-9]+$ && ${#frames} -le 7 ]] || { printf 'usage: %s [FRAME_COUNT; 0 = interactive]\n' "$0" >&2; exit 2; }
frames=$((10#$frames))
gpu start 800 480 --fullscreen
trap 'gpu stop' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sample() {
    local _tag user nice system idle wait irq softirq steal _rest key value _unit
    read -r _tag user nice system idle wait irq softirq steal _rest </proc/stat
    total=$((user+nice+system+idle+wait+irq+softirq+steal))
    idle=$((idle+wait))
    cpu=0
    if ((total > previous_total)); then
        cpu=$((100-100*(idle-previous_idle)/(total-previous_total)))
    fi
    previous_total=$total previous_idle=$idle
    local mem_total=0 mem_available=0
    while read -r key value _unit; do
        case $key in MemTotal:) mem_total=$value;; MemAvailable:) mem_available=$value;; esac
    done </proc/meminfo
    memory=$((mem_total ? 100*(mem_total-mem_available)/mem_total : 0))
    ((cpu < 0)) && cpu=0
    ((cpu > 100)) && cpu=100
    return 0
}

layout() {
    local _cols _rows pixels_x pixels_y
    read -r _cols _rows pixels_x pixels_y <<<"${ gpu size; }"
    width=${pixels_x:-800} height=${pixels_y:-480}
    ((width >= 320)) || width=320
    ((height >= 240)) || height=240
    ((width <= 1600)) || width=1600
    ((height <= 900)) || height=900
    gpu resize "$width" "$height"
    gx=52 gy=108 gw=$((width-76)) gh=$((height-168))
    right=$((gx+gw-1)) bottom=$((gy+gh-1))
    gpu clear 111827
    gpu text 24 20 f1f5f9 'SYSTEM / LIVE' 2
    gpu text 24 64 60a5fa 'CPU'
    gpu text 104 64 fbbf24 'MEMORY'
    gpu text 24 "$((height-30))" 94a3b8 'q quit   space pause   5 samples/s'
    gpu text 16 "$((gy-8))" 64748b '100'
    gpu text 24 "$((bottom-8))" 64748b '0'
    gpu rect "$((gx-1))" "$((gy-1))" "$((gw+2))" "$((gh+2))" 334155 1
    old_cpu_y=$((bottom-cpu*(gh-1)/100))
    old_mem_y=$((bottom-memory*(gh-1)/100))
    gpu present
}

previous_total=0 previous_idle=0 cpu=0 memory=0
sample
layout
paused=0 count=0 event=
while ((frames == 0 || count < frames)); do
    if gpu input event 200; then
        case $event in
            q|Q|ESC|CTRL-C) break;;
            ' ') paused=$((1-paused));;
            RESIZE:*) layout;;
        esac
    fi
    ((paused)) && continue
    sample
    cpu_y=$((bottom-cpu*(gh-1)/100))
    mem_y=$((bottom-memory*(gh-1)/100))
    gpu scroll -3 0 111827 "$gx" "$gy" "$gw" "$gh"
    gpu line "$((right-3))" "$old_mem_y" "$right" "$mem_y" fbbf24 1
    gpu line "$((right-3))" "$old_cpu_y" "$right" "$cpu_y" 60a5fa 1
    gpu present
    old_cpu_y=$cpu_y old_mem_y=$mem_y
    count=$((count+1))
done
gpu stop
