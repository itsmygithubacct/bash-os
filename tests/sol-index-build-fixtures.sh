#!/bin/bash
# SPDX-License-Identifier: MIT
# Build the index command's test fixtures into DEST. Must run through the
# build gate, after the targeted product build (it reads build/bash-*):
#   faults.so          LD_PRELOAD failure injection for the index writer
#   sha1-check         the trailer SHA-1 against FIPS vectors and SHA1DC,
#                      under ASan and UBSan
#   fuzz               libFuzzer harness over index.c's parsers and edits
#   index-sanitize.so  the index builtin and its helpers under ASan and UBSan,
#                      with load.sh to enable it and asan-path for LD_PRELOAD
set -euo pipefail
cd "$(dirname "$0")/.."
dest=${1:?artifact directory required}
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
CC=${CC:-cc}
FUZZ_CC=${FUZZ_CC:-clang}
. config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
[[ -f "$bt/config.h" ]] || { echo "build bash first ($bt/config.h missing)" >&2; exit 1; }
stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/helpers/builtins" "$stage/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$PWD" "$stage/helpers" index >/dev/null
inc=(-DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins"
     -I"$bt/examples/loadables" -I"$stage/helpers/builtins" -Iloadables/common)

"$CC" -O2 -Wall -Wextra -Werror -fPIC -shared tests/sol-index-faults.c -ldl \
  -o "$dest/faults.so"

"$CC" -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
  -fno-omit-frame-pointer "${inc[@]}" tests/sol-index-sha1.c \
  loadables/_sha1dc/sha1.c loadables/_sha1dc/ubc_check.c -o "$dest/sha1-check"

"$FUZZ_CC" -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
  -fno-omit-frame-pointer "${inc[@]}" tests/sol-index-fuzz.c -o "$dest/fuzz"

"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -fno-omit-frame-pointer "${inc[@]}" loadables/index.c \
  "$stage/helpers/builtins/"*.c -lz -o "$dest/index-sanitize.so"
"$CC" -print-file-name=libasan.so > "$dest/asan-path"
printf 'enable -f %q index || exit 1\n' "$dest/index-sanitize.so" > "$dest/load.sh"
echo "index fixtures: $dest"
