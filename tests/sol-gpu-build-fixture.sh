#!/usr/bin/env bash
# Compilation entry point: invoke through the campaign build gate.
set -euo pipefail
cd "$(dirname "$0")/.."
output=${1:?usage: sol-gpu-build-fixture.sh OUTPUT.so [--sanitize]}
flags=(-O2 -g -Wall -Wextra -Werror -fPIC -shared '-Wl,-Bsymbolic')
if [[ ${2:-} == --sanitize ]]; then flags+=(-O1 -fsanitize=address,undefined); fi
"${CC:-cc}" "${flags[@]}" tests/sol-gpu-driver.c -lm -o "$output"
# A portable missing-symbol library for the error-path oracle.
"${CC:-cc}" "${flags[@]}" -x c - -o "$output.missing.so" <<'C'
int sol_gpu_missing_entry;
C
