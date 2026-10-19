#!/usr/bin/env bash
# Build vi (and its _bl_key helper) with ASan/UBSan as a loadable and run
# the vi selftest, the helper-smoke vi cases and tests/opus-vi-dd.py on it.
# Compiles: run through the campaign build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" vi
HB="$d/helpers/builtins"
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -Wall -Wextra -Wno-unused-parameter \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$HB" -Iloadables/common \
  -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/vi.c "$HB"/_bl_key_*.c -lm -o "$d/vi.so"
printf 'set -e\nenable -f %q vi\n' "$d/vi.so" > "$d/load.sh"
export HELPER_LOAD_ENV="$d/load.sh" HELPER_ASAN_LIB=$("$CC" -print-file-name=libasan.so)
bin=$(cd "$(dirname "${1:-out/bash}")" && pwd)/$(basename "${1:-out/bash}")
BASH_ENV=$HELPER_LOAD_ENV LD_PRELOAD=$HELPER_ASAN_LIB \
  ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$bin" -c 'PATH=; vi selftest' > "$d/selftest.tap"
cat "$d/selftest.tap"
! grep -q '^not ok' "$d/selftest.tap"
python3 tests/opus-vi-dd.py "$bin"
