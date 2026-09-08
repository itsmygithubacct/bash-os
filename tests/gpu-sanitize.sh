#!/usr/bin/env bash
# Run the protocol suite with instrumented graphics and raster code.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
bash tests/gpu-module.sh "$scratch/gpu.so" --sanitize
GPU_MODULE="$scratch/gpu.so" GPU_ASAN_LIB=$("${CC:-cc}" -print-file-name=libasan.so) \
    python3 tests/gpu-smoke.py "${1:-out/bash}"
