#!/usr/bin/env bash
# Compile the production source; invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
bt="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined -DHAVE_CONFIG_H -Iloadables/common -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables" loadables/join.c -o "$d/join.so"
printf 'enable -f %q join || exit
' "$d/join.so" > "$d/load.sh"
printf '#!/bin/bash
export BASH_ENV=%q LD_PRELOAD=%q ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1
exec %q "$@"
' "$d/load.sh" "$(cc -print-file-name=libasan.so)" "$bin" > "$d/bash-join"
chmod +x "$d/bash-join"
python3 tests/sol-join-check.py "$d/bash-join"
python3 tests/join-reuse.py "$d/bash-join"
python3 tests/review-join-streams.py "$d/bash-join"
