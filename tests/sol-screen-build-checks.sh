#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only. Run through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?output directory required}
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
bash tests/sol-ptybroker-build-checks.sh "$output"
cp "$output/ptybroker-ubsan.so" "$output/ptybroker.so"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=undefined -fno-sanitize-recover=all \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" \
  loadables/screen.c loadables/_ptybroker/client.c loadables/_ptybroker/server.c \
  -ldl -lz -o "$output/screen.so"
sha256sum loadables/screen.c "$output/screen.so" "$output/ptybroker.so" \
  > "$output/screen-sha256.txt"
