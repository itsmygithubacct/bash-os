#!/usr/bin/env bash
# Run the real shell-state suite with instrumented head and sed modules.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
# Start with the pinned stock source, then apply exactly the build's patch.
tar -xOf "dl/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION").tar.gz" \
  "bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")/examples/loadables/head.c" > "$d/head.c"
patch --batch -s "$d/head.c" < patches/head-stdin.patch
# sed still carries its legacy loadable descriptor; mirror the static table's name.
sed -e 's/^struct builtin bashsed_struct/struct builtin sed_struct/' \
    -e 's/^    "bashsed",$/    "sed",/' loadables/sed.c > "$d/sed.c"
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" "$d/head.c" "$d/sed.c" -o "$d/head-sed.so"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport HEAD_SED_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/head-sed.so" "$(realpath "${1:-out/bash-core}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/head-sed-parity.py "$d/bash-os"
