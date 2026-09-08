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
EXPAND_PRELOAD=$("$CC" -print-file-name=libasan.so) EXPAND_MODULE="$d/expand.so" \
  python3 tests/expand-parity.py "${1:-out/bash}"
