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
