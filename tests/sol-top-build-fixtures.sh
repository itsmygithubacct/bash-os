#!/usr/bin/env bash
# Invoke through the build gate. This script only builds; tests never compile.
set -euo pipefail
cd "$(dirname "$0")/.."
evidence=${BASHOS_TASK_DIR:?set evidence directory}
if [[ ${TOP_SKIP_SHELL_BUILD:-0} != 1 ]]; then
  ./build.sh --include top --name sol-top
fi
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
mkdir -p "$evidence/sanitize/builtins" "$evidence/sanitize/examples/loadables"
cc -O2 -Wall -Wextra -fPIC -shared -U_FORTIFY_SOURCE tests/sol-top-proc-shim.c -ldl -o "$evidence/proc-shim.so"
python3 config/stage-helpers.py --stage "$PWD" "$evidence/sanitize" top
HB="$evidence/sanitize/builtins"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -U_FORTIFY_SOURCE -I"$BT" -I"$BT/include" -I"$HB" -Iloadables/common \
  -I"$BT/builtins" -I"$BT/examples/loadables" loadables/top.c \
  "$HB/_bl_key_bl_key.c" "$HB/_bl_screen_screen.c" -o "$evidence/sanitize/top.so"
printf 'enable -f %q top\n' "$evidence/sanitize/top.so" > "$evidence/sanitize/load.sh"
cc -print-file-name=libasan.so > "$evidence/sanitize/asan-path"
# Optional original-source replacement, for regression reproduction only.
if [[ -f "$evidence/top-before.c" ]]; then
  cc -O2 -fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H -U_FORTIFY_SOURCE \
    -I"$BT" -I"$BT/include" -I"$HB" -I"$BT/builtins" -I"$BT/examples/loadables" \
    "$evidence/top-before.c" "$HB/_bl_key_bl_key.c" "$HB/_bl_screen_screen.c" \
    -o "$evidence/top-before.so"
  printf 'enable -f %q top\n' "$evidence/top-before.so" > "$evidence/load-before.sh"
fi
