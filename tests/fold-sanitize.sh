#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" tests/fold-module.c -o "$d/fold.so"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport FOLD_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/fold.so" "$(realpath "${1:-out/bash-core}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/fold-parity.py "$d/bash-os"
