#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only. Invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
out=${1:?usage: sol-fsfreeze-build.sh OUTPUT_DIRECTORY [SOURCE]}
mkdir -p "$out"
flags=(-g -fPIC -shared -Wl,-Bsymbolic -Wall -Wextra -DHAVE_CONFIG_H
  -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
if [[ $# -ge 2 ]]; then flags+=("-DFSFREEZE_SOURCE=\"$2\""); fi
"${CC:-cc}" "${flags[@]}" -O2 tests/sol-fsfreeze-fixture.c -o "$out/fsfreeze.so"
"${CC:-cc}" "${flags[@]}" -O1 -fsanitize=address,undefined \
  tests/sol-fsfreeze-fixture.c -o "$out/fsfreeze-sanitize.so"
"${CC:-cc}" -print-file-name=libasan.so > "$out/asan-library.txt"
"${CC:-cc}" --version > "$out/compiler-version.txt"
