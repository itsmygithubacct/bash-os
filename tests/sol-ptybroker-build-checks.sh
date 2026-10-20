#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only: invoke through the campaign build gate.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
output=$1
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
mkdir -p "$output"
cc -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
  tests/sol-ptybroker-native.c loadables/_ptybroker/client.c -o "$output/native-sanitize"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=undefined -fno-sanitize-recover=all \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" \
  loadables/ptybroker.c loadables/_ptybroker/client.c loadables/_ptybroker/server.c \
  -ldl -o "$output/ptybroker-ubsan.so"
sha256sum loadables/ptybroker.c loadables/_ptybroker/{server,client}.c \
  tests/sol-ptybroker-native.c > "$output/source-sha256.txt"
