#!/usr/bin/env bash
# Invoke ONLY through the campaign build gate. Produces no measurements.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASHOS_TASK_DIR:?set an evidence/artifact directory}"
mkdir -p "$BASHOS_TASK_DIR"
source config/versions.sh
bt="build/bash-$BASH_SRC_VERSION"
cc=${CC:-cc}
"$cc" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -Iloadables/common \
  -I"$bt/builtins" -I"$bt/examples/loadables" loadables/bsdgames.c -lm \
  -o "$BASHOS_TASK_DIR/bsdgames-sanitize.so"
printf 'enable -f %q bsdgames || exit\n' "$BASHOS_TASK_DIR/bsdgames-sanitize.so" > "$BASHOS_TASK_DIR/load-sanitize.sh"
"$cc" -print-file-name=libasan.so > "$BASHOS_TASK_DIR/asan-library.txt"
# Garbage collection keeps only the production translation function called by
# the harness, discarding the unused Bash entrypoint and game adapters.
"$cc" -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -Iloadables/common \
  -I"$bt/builtins" -I"$bt/examples/loadables" tests/sol-bsdgames-transform.c \
  -lm -o "$BASHOS_TASK_DIR/transform"
