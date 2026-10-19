#!/usr/bin/env bash
# Build only; the caller MUST use the campaign build gate when applicable.
# Run the noncompiling Python integration test separately.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?usage: sol-bashlogger-build-fixtures.sh OUTPUT_DIRECTORY}
mkdir -p "$output"
output=$(cd "$output" && pwd)
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
cc=${CC:-cc}
"$cc" -O2 -g -Wall -Wextra -fPIC -shared tests/sol-bashlogger-syscalls.c -ldl -o "$output/syscalls.so"
"$cc" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -Iloadables/common -I"$bt" -I"$bt/include" -I"$bt/builtins" \
  -I"$bt/examples/loadables" loadables/bashlogger.c -o "$output/bashlogger-sanitize.so"
"$cc" -print-file-name=libasan.so > "$output/libasan.path"
"$cc" --version > "$output/compiler-version.txt"
