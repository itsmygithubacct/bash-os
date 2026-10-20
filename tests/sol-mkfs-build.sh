#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only. Invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set evidence directory}"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" -fPIC -shared -Wl,-Bsymbolic)
"${CC:-cc}" -O2 -g "${flags[@]}" tests/sol-mkfs-shim.c -o "$d/mkfs-shim.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" tests/sol-mkfs-shim.c -o "$d/mkfs-sanitize.so"
# Preserve and check starting defects separately from the fixed module.
if [[ -f $d/mkfs-baseline.c ]]; then
    "${CC:-cc}" -O2 -g "${flags[@]}" "-DMKFS_SOURCE=\"$d/mkfs-baseline.c\"" tests/sol-mkfs-shim.c -o "$d/mkfs-baseline.so"
fi
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
