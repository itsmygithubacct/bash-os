#!/usr/bin/env bash
# Compilation only. Invoke through the campaign build gate, then run tests
# separately. Usage: bash tests/sol-grep-build-harness.sh OUTPUT [BUILT-TREE]
set -euo pipefail
output=${1:?output path required}
tree=${2:-build/bash-5.3}
if [[ ! -f $tree/config.h ]]; then
  echo "missing configured Bash tree: $tree" >&2
  exit 1
fi
"${CC:-cc}" -O1 -g -fno-omit-frame-pointer -fno-pie -no-pie \
  -fsanitize=address,undefined -DHAVE_CONFIG_H \
  -I"$tree" -I"$tree/include" -I"$tree/builtins" -I"$tree/examples/loadables" \
  loadables/grep.c tests/grep-host.c -lpcre2-8 -o "$output"
