#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Package publication/rollback paths under ASan and UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -Iloadables/common loadables/pkg.c -o "$scratch/pkg.so"
PKG_TEST_LOADABLE="$scratch/pkg.so" PKG_TEST_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/pkg-safety.py "${1:-out/bash}"
