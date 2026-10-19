#!/usr/bin/env bash
# Build only; the caller MUST use the campaign build gate when applicable.
# Then: tests/opus-payload-installer.py BASH --module OUT/payload-sanitize.so \
#         --asan-runtime "$(cat OUT/libasan.path)"
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?usage: opus-payload-build-sanitizer.sh OUTPUT_DIRECTORY}
mkdir -p "$output"
output=$(cd "$output" && pwd)
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
cc=${CC:-cc}
"$cc" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -Wall -Wextra -Wno-unused-parameter \
  -DHAVE_CONFIG_H -Iloadables/common -I"$bt" -I"$bt/include" -I"$bt/builtins" \
  -I"$bt/lib" -I"$bt/examples/loadables" loadables/payload.c -o "$output/payload-sanitize.so"
"$cc" -print-file-name=libasan.so > "$output/libasan.path"
"$cc" --version > "$output/compiler-version.txt"
