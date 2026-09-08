#!/usr/bin/env bash
# Run with out/bash. Optional arguments: frame count and transport.
set -euo pipefail
frames=${1:-0} transport=${2:-dmabuf}
[[ $frames =~ ^[0-9]+$ && ${#frames} -le 7 ]] || { printf 'usage: %s [FRAME_COUNT] [auto|shm|inline|dmabuf]\n' "$0" >&2; exit 2; }
frames=$((10#$frames))
gpu start 800 480 --fullscreen --transport "$transport"
trap 'gpu stop' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
gpu clear 000000
gpu text 24 24 ffffff 'BASH / GPU' 3
gpu text 24 82 ffffff 'q quit' 1
gpu shader "${BASH_SOURCE[0]%/*}/gpu-shader.frag"
epoch=${EPOCHREALTIME/./}
count=0 event=
while ((frames == 0 || count < frames)); do
    now=${EPOCHREALTIME/./}
    elapsed=$((now-epoch))
    printf -v seconds '%d.%06d' "$((elapsed/1000000))" "$((elapsed%1000000))"
    gpu render "$seconds"
    gpu present
    count=$((count+1))
    if gpu input event 16; then
        case $event in q|Q|ESC|CTRL-C) break;; esac
    fi
done
gpu stop
