#!/usr/bin/env bash
# Instrument the crypto wrapper; unchanged primitives resolve from the tested
# full binary. tests/final-sanitize.sh instruments the vendored primitives too.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}; BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" crypto
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  -Iloadables/common -I"$d/helpers/builtins" loadables/crypto.c -o "$d/crypto.so"
printf 'enable -f %q crypto || exit\n' "$d/crypto.so" > "$d/load.sh"
CRYPTO_STATE_LOAD_ENV="$d/load.sh" CRYPTO_STATE_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/crypto-state.py "${1:-out/bash}"
