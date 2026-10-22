#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ptybroker create and terminate under a SIGCHLD storm, with ASan and UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
source config/versions.sh
BT="build/bash-$BASH_SRC_VERSION"
[[ -d $BT ]] || { echo 'secreview-ptybroker-sanitize: build tree missing'; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/ptybroker.c loadables/_ptybroker/client.c loadables/_ptybroker/server.c \
  -ldl -o "$d/ptybroker.so"
SECREVIEW_LOADABLE="$d/ptybroker.so" SECREVIEW_BUILTIN=ptybroker \
  SECREVIEW_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/secreview-shell-fds.py "${1:-out/bash}" ptybroker
