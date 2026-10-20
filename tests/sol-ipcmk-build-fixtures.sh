#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Compilation only: invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
OUT=${1:?fixture output directory required}
mkdir -p "$OUT"
flags=(-DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
# Optional archived starting source permits a nonmutating behavior receipt.
if [[ -f "${BASHOS_TASK_DIR:-}/ipcmk-start.c" ]]; then
    "${CC:-cc}" -O2 -fPIC -shared -Wl,-Bsymbolic "${flags[@]}" "$BASHOS_TASK_DIR/ipcmk-start.c" -o "$OUT/ipcmk-start.so"
fi
"${CC:-cc}" -O2 -g -fPIC -shared -Wl,-Bsymbolic "${flags[@]}" tests/sol-ipcmk-kernel.c -o "$OUT/kernel.so" -lrt -pthread
"${CC:-cc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie "${flags[@]}" tests/sol-ipcmk-fixture.c -o "$OUT/fixture-sanitize" -lrt -pthread
# Instrument the real builtin and oracle for the same real kernel tests.
"${CC:-cc}" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined "${flags[@]}" loadables/ipcmk.c -o "$OUT/ipcmk-sanitize.so" -lrt -pthread
"${CC:-cc}" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined "${flags[@]}" tests/sol-ipcmk-kernel.c -o "$OUT/kernel-sanitize.so" -lrt -pthread
printf 'enable -f %q ipcmk || exit 99\n' "$OUT/ipcmk-sanitize.so" > "$OUT/sanitize-env.sh"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport BASH_ENV=%q\nexec %q "$@"\n' \
    "$("${CC:-cc}" -print-file-name=libasan.so)" "$OUT/sanitize-env.sh" "$(realpath "${2:-out/bash-sol-ipcmk}")" > "$OUT/bash-sanitize"
chmod +x "$OUT/bash-sanitize"
