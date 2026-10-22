#!/bin/sh
# Invoke only under gated.py build. The benchmark never compiles anything.
set -eu
out=$1
cc -std=gnu11 -Wall -Wextra -O2 -U_FORTIFY_SOURCE -fPIC -shared bench/sol-pgrep-proc-shim.c -ldl -o "$out/proc-shim.so"
cc -std=gnu11 -Wall -Wextra -g -O1 -U_FORTIFY_SOURCE -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -I tests/sol-pgrep-stubs tests/sol-pgrep-harness.c -o "$out/pgrep-sanitize"
