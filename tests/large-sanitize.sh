#!/usr/bin/env bash
# Exercise complex import parsers with instrumented runtime loadables.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
names=(awk jq bc vec coreutils fdisk dhcpd curl bsdgames)
printf 'set -e\n' > "$d/load.sh"
for name in "${names[@]}"; do
  "$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
    -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -Iloadables/common \
    -I"$BT/builtins" -I"$BT/examples/loadables" "loadables/$name.c" -lm -o "$d/$name.so"
  printf 'enable -f %q %q\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
LARGE_LOAD_ENV="$d/load.sh" LARGE_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/large-smoke.py "${1:-out/bash}" "${names[@]}"
