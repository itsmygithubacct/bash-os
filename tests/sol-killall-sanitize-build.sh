#!/bin/bash
# Invoke through the campaign build gate after a targeted shell build.
set -euo pipefail
: "${BASHOS_TASK_DIR:?set an evidence/output directory}"
source_dir=$PWD/build/bash-5.3
cc -O1 -g -fPIC -shared -fsanitize=address,undefined -fno-omit-frame-pointer \
    -U_FORTIFY_SOURCE \
    -I"$source_dir" -I"$source_dir/include" -I"$source_dir/builtins" \
    -I"$source_dir/examples/loadables" -Wl,-Bsymbolic \
    loadables/pgrep.c loadables/killall.c -o "$BASHOS_TASK_DIR/sol-killall-sanitize.so"
cc -print-file-name=libasan.so > "$BASHOS_TASK_DIR/asan-runtime.txt"
