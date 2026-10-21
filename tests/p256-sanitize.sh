#!/usr/bin/env bash
# Instrument crypto, acme, and their staged helpers, then run the P-256 fixtures.
# A wrapper-only preload does not cover the arithmetic these commands call.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" crypto acme
flags=(-O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables"
       -Iloadables/common -I"$d/helpers/builtins")
i=0
for source in "$d/helpers/builtins/"*.c loadables/crypto.c loadables/acme.c; do
  obj=$(printf '%03d-%s.o' "$i" "$(basename "${source%.c}")")
  "$CC" "${flags[@]}" -c "$source" -o "$d/objects/$obj"
  i=$((i+1))
done
"$CC" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o \
  -lm -lpthread -o "$d/p256.so"
# Load the instrumented builtins only in the tested Bash. A helper that execs
# another shell must not enable this ABI.
target=$(realpath "${1:-out/bash}")
printf '[[ $BASH == %q ]] || return 0\nset -e\n' "$target" > "$d/load.sh"
printf 'enable -f %q crypto\nenable -f %q acme\n' "$d/p256.so" "$d/p256.so" >> "$d/load.sh"
"$CC" -O2 -fsanitize=address,undefined -fno-omit-frame-pointer \
  tests/p256-m-check.c -o "$d/p256-m-check"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$d/p256-m-check"
P256_LOAD_ENV="$d/load.sh" \
  P256_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/p256-check.py "$target"
