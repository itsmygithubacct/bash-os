#!/usr/bin/env bash
# Compile only; invoke through the campaign build gate after the targeted build.
set -euo pipefail
cd "$(dirname "$0")/.."
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
output=${1:?usage: sol-setpgid-build-ubsan.sh OUTPUT-DIRECTORY}
mkdir -p "$output"
"${CC:-cc}" -O1 -g -fPIC -shared -Wl,-Bsymbolic \
  -fsanitize=undefined -fno-sanitize-recover=all \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" \
  -I"$bt/examples/loadables" "$bt/builtins/setpgid.c" \
  -o "$output/setpgid-ubsan.so"
