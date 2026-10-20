#!/usr/bin/env bash
# Invoke only through gated.py build. No compilation in the Python test.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?}"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
out="$BASHOS_TASK_DIR/sanitize"
mkdir -p "$out"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" \
  -I"$bt/examples/loadables" loadables/pcre.c -lpcre2-8 -o "$out/pcre.so"
printf 'enable -f %q pcre\n' "$out/pcre.so" > "$out/load.sh"
cc -print-file-name=libasan.so > "$out/asan-runtime.txt"
