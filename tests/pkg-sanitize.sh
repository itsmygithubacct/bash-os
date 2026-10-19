#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Package publication, rollback and trust-file errors under ASan and UBSan.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/helpers/builtins" "$scratch/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$scratch/helpers" pkg >/dev/null
HB="$scratch/helpers/builtins"
# pkg.c only calls the SHA-256 and Ed25519 entry points. Staging the helper
# trees rewrites their includes to the flattened names pkg.c already uses;
# the rest of the crypto tree is not part of this loadable.
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$HB" -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -Iloadables/common \
  loadables/pkg.c "$HB"/_mbedtls_sha256.c \
  "$HB"/_monocypher_monocypher-ed25519.c -llzma -o "$scratch/pkg.so"
for suite in pkg-safety pkg-trust; do
  PKG_TEST_LOADABLE="$scratch/pkg.so" PKG_TEST_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
    python3 "tests/$suite.py" "${1:-out/bash}"
done
