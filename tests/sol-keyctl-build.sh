#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only: run through the build resource gate, after build.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set an evidence directory}"
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins"
       -I"$bt/examples/loadables" -fPIC -shared -Wl,-Bsymbolic)
"${CC:-cc}" -O2 -g "${flags[@]}" tests/sol-keyctl-shim.c -o "$d/keyctl-shim.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  "${flags[@]}" tests/sol-keyctl-shim.c -o "$d/keyctl-sanitize.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  "${flags[@]}" loadables/keyctl.c -o "$d/keyctl-real-sanitize.so"
if [[ -f $d/keyctl-baseline.c ]]; then
  "${CC:-cc}" -O2 -g "${flags[@]}" "-DKEYCTL_SOURCE=\"$d/keyctl-baseline.c\"" \
    tests/sol-keyctl-shim.c -o "$d/keyctl-baseline.so"
fi
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
