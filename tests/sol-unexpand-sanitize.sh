#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Invoke through the campaign build gate: this script compiles a module.
set -euo pipefail
cd "$(dirname "$0")/.."
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"${CC:-cc}" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
 -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
 -I"$BT/examples/loadables" loadables/unexpand.c -o "$d/unexpand.so"
UNEXPAND_PRELOAD=$("${CC:-cc}" -print-file-name=libasan.so) UNEXPAND_MODULE="$d/unexpand.so" \
 python3 tests/sol-unexpand-parity.py "${1:-out/bash}"
