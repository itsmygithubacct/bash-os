#!/usr/bin/env bash
# tests/pr-sanitize.sh [BINARY] — the pr parity and shell-state checks again,
# with pr rebuilt under AddressSanitizer and UndefinedBehaviorSanitizer and
# loaded over the compiled-in builtin.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" \
  loadables/pr.c -o "$d/pr.so"
# Keep instrumentation confined to the Bash subprocess; host GNU pr stays ordinary.
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport PR_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/pr.so" "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/pr-parity.py "$d/bash-os"
