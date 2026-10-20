#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only; invoke through the build gate after the targeted shell build.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set evidence directory}"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -fPIC -shared -Iloadables/common -I"$bt" -I"$bt/include"
       -I"$bt/builtins" -I"$bt/examples/loadables")
"${CC:-cc}" -O2 -g "${flags[@]}" tests/sol-halt-shim.c -o "$d/boundary.so"
for name in poweroff halt reboot; do
  # Bind the builtin struct to this module's instrumented entry point, even
  # when the shell exports an identically named production function.
  # Undefined reboot/sync/accounting symbols still resolve to the preload shim.
  "${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -Wl,-Bsymbolic-functions "${flags[@]}" "loadables/$name.c" \
    -o "$d/$name-sanitize.so"
done
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
