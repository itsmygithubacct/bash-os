#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}; BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
for name in at crontab; do
  "$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
    -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
    "loadables/$name.c" -o "$d/$name.so"
  printf 'enable -f %q %q || exit\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
SPOOL_LOAD_ENV="$d/load.sh" SPOOL_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/cron-spool.py "${1:-out/bash}"
