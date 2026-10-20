#!/usr/bin/env bash
# Run through the campaign build gate: this script compiles a production module.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d "$HERE/out/sol-wc-sanitize.XXXXXX")
trap 'rm -rf "$d"' EXIT
sed -e 's/^struct builtin bashwc_struct/struct builtin wc_struct/' \
    -e 's/^    "bashwc",$/    "wc",/' loadables/wc.c > "$d/wc.c"
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" "$d/wc.c" -o "$d/wc.so"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport SOL_WC_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/wc.so" \
  "$(realpath "${1:-out/bash-sol-wc-after}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/sol-wc-check.py "$d/bash-os"
