#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only: invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
artifact=${1:?artifact directory}
mkdir -p "$artifact"
sha256sum loadables/losetup.c tests/sol-losetup-shim.c > "$artifact/module-sources.sha256"
bt="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
flags=(-g -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H
  -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
"${CC:-cc}" -O2 "${flags[@]}" tests/sol-losetup-shim.c -o "$artifact/losetup-fixture.so"
"${CC:-cc}" -O1 -fsanitize=address,undefined "${flags[@]}" tests/sol-losetup-shim.c -o "$artifact/losetup-sanitize.so"
"${CC:-cc}" -print-file-name=libasan.so > "$artifact/libasan-path"
"${CC:-cc}" --version > "$artifact/compiler-version.txt"
sha256sum -c "$artifact/module-sources.sha256"
