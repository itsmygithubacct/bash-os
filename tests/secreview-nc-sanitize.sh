#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Closed-stdout SIGPIPE dispositions for nc under ASan and UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
source config/versions.sh
BT="build/bash-$BASH_SRC_VERSION"
[[ -d $BT ]] || { echo 'secreview-nc-sanitize: build tree missing'; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/nc.c -o "$d/nc.so"
SECREVIEW_LOADABLE="$d/nc.so" SECREVIEW_BUILTIN=nc \
  SECREVIEW_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/secreview-shell-sigpipe.py "${1:-out/bash}" nc
