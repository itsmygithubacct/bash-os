#!/usr/bin/env bash
# Build the runtime module with its selected helper in an isolated directory.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
target=${1:?usage: gpu-module.sh OUTPUT.so [--sanitize]}
BT=${GPU_BASH_TREE:-build/bash-5.3}
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/builtins" "$scratch/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$scratch" gpu >/dev/null
flags=(-O2 -g -Wall -Wextra -Werror -fPIC -shared '-Wl,-Bsymbolic' -DHAVE_CONFIG_H
       -Iloadables/common -I"$scratch/builtins"
       -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
if [[ ${2:-} == --sanitize ]]; then flags+=(-O1 '-fsanitize=address,undefined'); fi
"${CC:-cc}" "${flags[@]}" loadables/gpu.c "$scratch/builtins/_soft_raster_soft_raster.c" -ldl -lm -o "$target"
