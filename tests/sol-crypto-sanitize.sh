#!/usr/bin/env bash
# Run through the campaign build gate: compiles crypto and its selected helpers.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set evidence directory}"
binary=$(realpath "${1:-out/bash}")
d="$BASHOS_TASK_DIR/sanitize"
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects"
python3 config/stage-helpers.py --stage "$PWD" "$d/helpers" crypto
bt=build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")
flags=(-O1 -g -fPIC -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables"
       -Iloadables/common -I"$d/helpers/builtins")
for source in "$d/helpers/builtins/"*.c loadables/crypto.c; do
    "${CC:-cc}" "${flags[@]}" -c "$source" -o "$d/objects/$(basename "${source%.c}").o"
done
"${CC:-cc}" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o -lpthread -o "$d/crypto.so"
printf 'enable -f %q crypto || exit\n' "$d/crypto.so" > "$d/load.sh"
export CRYPTO_STATE_LOAD_ENV="$d/load.sh"
export CRYPTO_STATE_ASAN_LIB=$("${CC:-cc}" -print-file-name=libasan.so)
python3 tests/crypto-state.py "$binary"
python3 tests/sol-crypto-check.py "$binary"
FINAL_LOAD_ENV="$d/load.sh" FINAL_ASAN_LIB="$CRYPTO_STATE_ASAN_LIB" python3 tests/final-smoke.py "$binary" crypto
