#!/usr/bin/env bash
# Build only mail and its declared helpers; invoke through the build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set the evidence directory}"
source config/versions.sh
bt="$PWD/build/bash-$BASH_SRC_VERSION"
d="$BASHOS_TASK_DIR/sanitize"
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects"
python3 config/stage-helpers.py --stage "$PWD" "$d/helpers" mail
flags=(-O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables"
       -I"$d/helpers/builtins" -Iloadables/common)
for src in "$d/helpers/builtins/"*.c loadables/mail.c; do
    "${CC:-cc}" "${flags[@]}" -c "$src" -o "$d/objects/$(basename "${src%.c}").o"
done
"${CC:-cc}" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o -lpthread -o "$d/mail.so"
printf 'enable -f %q mail\n' "$d/mail.so" > "$d/load.sh"
"${CC:-cc}" -print-file-name=libasan.so > "$d/asan-runtime.txt"
