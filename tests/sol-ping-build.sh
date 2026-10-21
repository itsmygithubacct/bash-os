#!/usr/bin/env bash
# Run this script through gated.py build; it never runs a measurement.
set -euo pipefail
output=${1:?output directory required}
mkdir -p "$output"
bt=build/bash-5.3
flags=(-DHAVE_CONFIG_H -fPIC -I"$bt" -I"$bt/include" -I"$bt/builtins" -I"$bt/examples/loadables")
cc -O2 -shared -Wl,-Bsymbolic "${flags[@]}" tests/sol-ping-fixture.c -lm -o "$output/fixture.so"
cc -O1 -g -shared -Wl,-Bsymbolic -fsanitize=address,undefined "${flags[@]}" tests/sol-ping-fixture.c -lm -o "$output/fixture-sanitize.so"
cc -print-file-name=libasan.so > "$output/asan-runtime.txt"
{
  cc --version
  printf 'normal: cc -O2 -shared -Wl,-Bsymbolic %s -lm\n' "${flags[*]}"
  printf 'sanitizer: cc -O1 -g -shared -Wl,-Bsymbolic -fsanitize=address,undefined %s -lm\n' "${flags[*]}"
  sha256sum loadables/ping.c tests/sol-ping-fixture.c "$output/fixture.so" "$output/fixture-sanitize.so"
} > "$output/build.txt"
