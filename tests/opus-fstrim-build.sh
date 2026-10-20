#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only; invoke through the campaign build gate after
# ./build.sh --include fstrim has configured the bash tree.
#   fstrim.so           production fstrim.c behind the closed fixture shim
#   fstrim-sanitize.so  the same under AddressSanitizer and UBSan
#   fitrim-preload.so   FITRIM interposer for the util-linux oracle
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set an artifact directory}"
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
[[ -f $bt/config.h ]] || { echo 'Build the targeted shell first' >&2; exit 1; }
d="$BASHOS_TASK_DIR/artifacts"
mkdir -p "$d"
flags=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables"
       -Wall -Wextra -Wno-unused-parameter -fPIC -shared -Wl,-Bsymbolic)
"${CC:-cc}" -O2 -g "${flags[@]}" tests/opus-fstrim-shim.c -o "$d/fstrim.so"
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" \
  tests/opus-fstrim-shim.c -o "$d/fstrim-sanitize.so"
"${CC:-cc}" -O2 -g -Wall -Wextra -fPIC -shared tests/opus-fstrim-preload.c -o "$d/fitrim-preload.so" -ldl
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-path.txt"
"${CC:-cc}" --version > "$d/compiler-version.txt"
