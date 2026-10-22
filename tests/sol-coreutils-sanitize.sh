#!/usr/bin/env bash
# Run this entire script through the campaign build gate: it compiles modules.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
for name in coreutils tac; do
  fixture=()
  fortify=()
  if [[ $name == coreutils ]]; then
    fixture=(tests/sol-coreutils-random.c -Wl,--wrap=fopen)
    fortify=(-U_FORTIFY_SOURCE)
  fi
  "$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
    -DHAVE_CONFIG_H "${fortify[@]}" -Iloadables/common -I"$BT" -I"$BT/include" \
    -I"$BT/builtins" -I"$BT/examples/loadables" "loadables/$name.c" "${fixture[@]}" -lm -o "$d/$name.so"
  printf 'enable -f %q %q\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
export COREUTILS_TEST_LOAD="$d/load.sh" COREUTILS_TEST_ASAN=$("$CC" -print-file-name=libasan.so)
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
python3 tests/sol-coreutils-check.py "${1:-out/bash}"
python3 tests/sol-coreutils-random-check.py "${1:-out/bash}"
