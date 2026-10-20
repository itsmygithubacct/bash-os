#!/usr/bin/env bash
# Compile only under the campaign build gate. Test the production stock patch
# as a module in the real shell, with the complete head option/state suite.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
: "${BASHOS_TASK_DIR:?evidence directory required}"
CC=${CC:-cc}
. config/versions.sh
BT="$HERE/build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/sanitize"
mkdir -p "$d"
tar -xOf "dl/bash-$BASH_SRC_VERSION.tar.gz" "bash-$BASH_SRC_VERSION/examples/loadables/head.c" > "$d/head.c"
patch --batch -s "$d/head.c" < patches/head-stdin.patch
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" "$d/head.c" -o "$d/head.so"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport SOL_HEAD_MODULE=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/head.so" "$(realpath "${1:-out/bash-sol-head}")" > "$d/bash-os"
chmod +x "$d/bash-os"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/sol-head-options.py "$d/bash-os"
