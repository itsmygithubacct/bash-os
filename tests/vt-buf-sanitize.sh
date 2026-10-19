#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The terminal and the line buffer under ASan and UBSan, on the sequences
# that overflowed a cell encoding or freed a buffer's memory twice.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
[[ -d $BT ]] || { echo 'vt-buf-sanitize: build tree missing; run ./build.sh first'; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" vt >/dev/null
HB="$d/helpers/builtins"
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
       -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$HB" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
"$CC" "${flags[@]}" loadables/vt.c "$HB"/_libgrapheme_*.c -lm -o "$d/vt.so"
"$CC" "${flags[@]}" loadables/buf.c -o "$d/buf.so"
printf 'enable -f %q vt || exit\nenable -f %q buf || exit\n' "$d/vt.so" "$d/buf.so" > "$d/load.sh"
VTBUF_LOAD_ENV="$d/load.sh" VTBUF_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/vt-buf-edges.py "${1:-out/bash}"
