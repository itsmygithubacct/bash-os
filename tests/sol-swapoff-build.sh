#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compile only, always through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set an artifact directory}"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables"
       -fPIC -shared)
"${CC:-cc}" -O2 -g -Wall -Wextra "${flags[@]}" tests/sol-swapoff-shim.c -ldl -o "$d/swapoff-shim.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" \
    loadables/swapoff.c -o "$d/swapoff-sanitize.so"
if [[ -f $d/swapoff-baseline.c ]]; then
    "${CC:-cc}" -O2 -g "${flags[@]}" "$d/swapoff-baseline.c" -o "$d/swapoff-baseline.so"
fi
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
