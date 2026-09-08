#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" \
  loadables/nl.c -o "$d/nl.so"
# Keep instrumentation confined to the Bash subprocess; host GNU tools stay ordinary.
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport NL_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/nl.so" "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/nl-parity.py "$d/bash-os"
