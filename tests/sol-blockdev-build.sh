#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only; invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set an artifact directory}"
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
[[ -f $bt/config.h ]] || { echo 'Build the targeted shell first' >&2; exit 1; }
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables"
       -fPIC -shared -Wl,-Bsymbolic)
"${CC:-cc}" -O2 -g "${flags[@]}" tests/sol-blockdev-shim.c -o "$d/blockdev.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" \
  tests/sol-blockdev-shim.c -o "$d/blockdev-sanitize.so"
if [[ -f $d/blockdev-baseline.c ]]; then
  "${CC:-cc}" -O2 -g "${flags[@]}" "-DBLOCKDEV_SOURCE=\"$d/blockdev-baseline.c\"" \
    tests/sol-blockdev-shim.c -o "$d/blockdev-baseline.so"
fi
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
