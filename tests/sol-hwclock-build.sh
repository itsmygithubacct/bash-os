#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only. Run through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set the artifact directory}"
. config/versions.sh
./build.sh --include hwclock --name sol-hwclock
bt="build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
set -x
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
"${CC:-cc}" -O2 -g "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic tests/sol-hwclock-shim.c -lm -o "$d/hwclock.so"
"${CC:-cc}" -O1 -g "${flags[@]}" -DHWCLOCK_STANDALONE -fsanitize=address,undefined,float-cast-overflow \
    -fno-omit-frame-pointer -no-pie tests/sol-hwclock-shim.c -lm -o "$d/hwclock-sanitize"
if [[ -f $d/hwclock-baseline.c ]]; then
  "${CC:-cc}" -O2 -g "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic \
      "-DHWCLOCK_SOURCE=\"$d/hwclock-baseline.c\"" tests/sol-hwclock-shim.c -lm -o "$d/hwclock-baseline.so"
fi
"${CC:-cc}" --version > "$d/compiler-version.txt"
