#!/usr/bin/env bash
# Compiles production sed; invoke through the campaign build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
CC=${CC:-cc}
BT=${BASH_BUILD_DIR:-build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")}
BX=$(realpath "${1:-out/bash-sol-sed}")
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
sed -e 's/^struct builtin bashsed_struct/struct builtin sed_struct/' \
    -e 's/^    "bashsed",$/    "sed",/' loadables/sed.c > "$d/sed.c"
for backend in system portable; do
  flags=()
  [[ $backend != portable ]] || flags=(-DBASHSED_PORTABLE_REGEX=1 -DBASHSED_PORTABLE_PEEK=1)
  "$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
    -fno-omit-frame-pointer -DHAVE_CONFIG_H "${flags[@]}" \
    -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" \
    -I"$BT/examples/loadables" "$d/sed.c" -o "$d/sed.so"
  printf 'enable -f %q sed || exit\n' "$d/sed.so" > "$d/load.sh"
  printf '#!/bin/bash\nexport BASH_ENV=%q\nexport LD_PRELOAD=%q\nexec %q "$@"\n' \
    "$d/load.sh" "$("$CC" -print-file-name=libasan.so)" "$BX" > "$d/bash-os"
  chmod +x "$d/bash-os"
  export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
  for suite in head-sed-parity sol-sed-parity sol-sed-complete sol-sed-binary-regex sol-sed-signals; do
    printf '%s %s\n' "$backend" "$suite"
    python3 "tests/$suite.py" "$d/bash-os"
  done
done
