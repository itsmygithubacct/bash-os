#!/usr/bin/env bash
# Run this script through the campaign build gate. Tests never compile.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?output directory required}
mkdir -p "$output"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
[[ -f $bt/config.h ]] || { echo 'Build the targeted shell first' >&2; exit 1; }
includes=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
common=(-std=gnu11 -g -O2 -fPIC -shared -Wl,-Bsymbolic -Wall -Wextra)
cc "${common[@]}" "${includes[@]}" tests/sol-ipcctl-shim.c -o "$output/ipcctl-shim.so"
cc "${common[@]}" "${includes[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer \
   tests/sol-ipcctl-shim.c -o "$output/ipcctl-shim-sanitize.so"
if [[ $# -ge 2 ]]; then
    cc "${common[@]}" "${includes[@]}" "-DIPCCTL_SOURCE=\"$2\"" \
       tests/sol-ipcctl-shim.c -o "$output/ipcctl-shim-before.so"
fi
cc -print-file-name=libasan.so > "$output/asan-path.txt"
cc --version > "$output/compiler.txt"
