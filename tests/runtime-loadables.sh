#!/usr/bin/env bash
# Check exported registration names and execution through enable -f.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
BX=$(readlink -f "${1:-out/bash}")
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
for name in cut grep sort seq; do
  # Bind the loaded implementation locally even when the executable exports
  # an older builtin with the same function name.
  "${CC:-cc}" -O2 -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H \
    -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
    "loadables/$name.c" -o "$d/$name.so" -lm
done
"$BX" -e -c '
  PATH=
  for name in cut grep sort seq; do enable -f "$1/$name.so" "$name"; done
  [[ $(printf "a:b:c\n" | cut -d: -f2) == b ]]
  [[ $(printf "a\nb\na\n" | grep -c a) == 2 ]]
  [[ $(printf "10\n-2\n3\n" | sort -n) == $'"'"'-2\n3\n10'"'"' ]]
  [[ $(seq -s, 3) == 1,2,3 ]]
  rc=0; grep a <<< a > /dev/full 2>/dev/null || rc=$?
  [[ $rc == 2 ]]
  printf "runtime-loadables: four shared objects loaded and checked\n"
' _ "$d"
