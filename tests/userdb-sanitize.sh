#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}; BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/userdb.c -o "$d/userdb.so"
printf 'enable -f %q userdb || exit\n' "$d/userdb.so" > "$d/load.sh"
USERDB_LOAD_ENV="$d/load.sh" USERDB_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/userdb-records.py "${1:-out/bash}"
