#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run expand's parity and persistent-shell checks with an instrumented module.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" loadables/expand.c -o "$d/expand.so"
export EXPAND_PRELOAD=$("$CC" -print-file-name=libasan.so) EXPAND_MODULE="$d/expand.so"
python3 tests/expand-parity.py "${1:-out/bash}"
python3 tests/sol-expand-options.py "${1:-out/bash}"

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 REVIEW_MODULE="$EXPAND_MODULE" LD_PRELOAD="$EXPAND_PRELOAD" python3 tests/review-expand-descriptors.py "${1:-out/bash}"
