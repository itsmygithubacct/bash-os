#!/usr/bin/env bash
# lpr delivery, cancellation and spool cleanup under ASan+UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}; BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
[[ -d $BT ]] || { echo 'opus-lpr-sanitize: build tree missing; run ./build.sh first'; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  -Iloadables/common loadables/lpr.c -o "$d/lpr.so"
printf 'enable -f %q lpr || exit\n' "$d/lpr.so" > "$d/load.sh"
LPR_LOAD_ENV="$d/load.sh" LPR_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/opus-lpr-delivery.py "${1:-out/bash}"
# Cancel racing a reader that closes before the control-FIFO write: the shim
# holds the open until the test has closed the reader. Plain module, so the
# shim can be preloaded without the sanitizer runtime.
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic \
  -DHAVE_CONFIG_H -U_FORTIFY_SOURCE -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  -Iloadables/common loadables/lpr.c -o "$d/lpr-plain.so"
"$CC" -O1 -U_FORTIFY_SOURCE -fPIC -shared tests/opus-lpr-cancel-sigpipe-preload.c -o "$d/shim.so" -ldl
python3 tests/opus-lpr-cancel-sigpipe.py "${1:-out/bash}" "$d/lpr-plain.so" "$d/shim.so"
