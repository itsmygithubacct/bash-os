#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run the GNU compatibility fixtures with instrumented command modules.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
source config/versions.sh
tree="build/bash-$BASH_SRC_VERSION"
cc=${CC:-cc}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/helpers/builtins" "$scratch/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$root" "$scratch/helpers" sha256sum
helpers="$scratch/helpers/builtins"
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
       -DHAVE_CONFIG_H -I"$tree" -I"$tree/include" -I"$tree/builtins"
       -I"$tree/examples/loadables" -Iloadables/common -I"$helpers")
for name in base64 cat cp touch gzip sha256sum tar; do
    sources=("loadables/$name.c")
    libraries=()
    case "$name" in
        cp|touch)
            cat > "$scratch/$name-struct.c" <<EOF
#include <config.h>
#include "loadables.h"
extern int ${name}_builtin(WORD_LIST *);
extern char *${name}_doc[];
struct builtin ${name}_struct = {"$name", ${name}_builtin, BUILTIN_ENABLED, ${name}_doc, "$name", 0};
EOF
            sources+=("$scratch/$name-struct.c") ;;
        sha256sum) sources+=("$helpers/_mbedtls_sha256.c") ;;
        gzip) libraries+=(-lz) ;;
        tar) sources+=(loadables/pax.c); libraries+=(-lz) ;;
    esac
    "$cc" "${flags[@]}" "${sources[@]}" "${libraries[@]}" -o "$scratch/$name.so"
    printf 'enable -f %q %q || return\n' "$scratch/$name.so" "$name" >> "$scratch/load.sh"
done
BASHOS_GNU_TEST_LOAD="$scratch/load.sh" BASHOS_GNU_ASAN_LIB=$("$cc" -print-file-name=libasan.so) \
    python3 tests/gnu-command-compat.py "${1:-out/bash}"
