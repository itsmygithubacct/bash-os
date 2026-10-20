#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run this script through the campaign build gate. Never compile in correctness tests.
set -euo pipefail
cd "$(dirname "$0")/.."
output=$(realpath -m "${1:?fixture output directory required}")
mkdir -p "$output"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
cc=${CC:-cc}
"$cc" -O2 -Wall -Wextra -fPIC -shared tests/sol-renice-fixture.c -o "$output/fixture.so"
"$cc" -O2 -Wall -Wextra tests/fixtures/deny-wrapper-syscall.c -o "$output/deny-syscall"
"$cc" -O1 -g -Wall -Wextra -fPIC -shared -Wl,-Bsymbolic \
  -fsanitize=address,undefined -DHAVE_CONFIG_H \
  -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" \
  -Iloadables/common loadables/renice.c -o "$output/renice-sanitized.so"
"$cc" -print-file-name=libasan.so > "$output/asan-runtime"
