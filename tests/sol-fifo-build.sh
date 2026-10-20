#!/usr/bin/env bash
# Run this compilation helper through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
artifacts=$(cd "$1" && pwd)
./build.sh --include fifo --name sol-fifo --no-strip
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H
       -I"$bt" -I"$bt/include" -Iloadables/common
       -I"$bt/builtins" -I"$bt/examples/loadables")
"${CC:-cc}" "${flags[@]}" -fsanitize=address,undefined loadables/fifo.c -o "$artifacts/fifo-sanitize.so"
"${CC:-cc}" -print-file-name=libasan.so > "$artifacts/asan-library.txt"
if [[ -f $artifacts/fifo-baseline.c ]]; then
    "${CC:-cc}" "${flags[@]}" "$artifacts/fifo-baseline.c" -o "$artifacts/fifo-baseline.so"
fi
