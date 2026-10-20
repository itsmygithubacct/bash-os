#!/bin/sh
# Run only through gated.py build. Benchmarks/tests never compile.
set -eu
out=$1
name=${2:-sol-pkill}
./build.sh --include pkill,pgrep,killall,killall5 --name "$name"
cc -std=gnu11 -Wall -Wextra -Werror -O2 -fPIC -shared \
    tests/sol-pkill-intercept.c -ldl -o "$out/pkill-intercept.so"
cc -std=gnu11 -Wall -Wextra -Werror -g -O1 -fsanitize=address,undefined \
    -fno-omit-frame-pointer -no-pie -I tests/sol-pgrep-stubs \
    tests/sol-pkill-harness.c -o "$out/pkill-sanitize"
sh tests/sol-pgrep-tools-build.sh "$out"
