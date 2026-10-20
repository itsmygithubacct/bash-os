#!/bin/bash
# Invoke through the campaign build gate. Compilation is deliberately explicit.
set -euo pipefail
: "${BASHOS_TASK_DIR:?set BASHOS_TASK_DIR to a local artifact directory}"
cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -Wall -Wextra tests/sol-rtspcat-core.c -o "$BASHOS_TASK_DIR/core-sanitize"
cc -std=c11 -D_GNU_SOURCE -DRTSPCAT_STANDALONE -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -Wall -Wextra loadables/rtspcat.c -o "$BASHOS_TASK_DIR/rtspcat-sanitize"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 "$BASHOS_TASK_DIR/core-sanitize"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 python3 tests/sol-rtspcat-loopback.py --binary "$BASHOS_TASK_DIR/rtspcat-sanitize" --standalone --report "$BASHOS_TASK_DIR/sanitize-cases.json"
