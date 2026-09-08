#!/usr/bin/env bash
# Run full RISC-V behavior fixtures through QEMU. Guest exec needs binfmt support.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
binary=$(realpath "${1:?usage: tests/cross-smoke.sh BINARY}")
runner=$(command -v "${QEMU_RISCV64:-qemu-riscv64}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf '#!/bin/bash\nexec %q %q "$@"\n' "$runner" "$binary" > "$d/bash-os"
chmod +x "$d/bash-os"
BASH_OS_RUNNER="$runner" python3 tests/profile-smoke.py "$binary"
"$d/bash-os" -e -o pipefail -c '
  PATH=
  [[ $(printf "compression fixture" | zstd -c - | zstd -dc -) == "compression fixture" ]]
  "$BASH" -c "[[ 2+3 -eq 5 ]]"
'
python3 tests/helper-smoke.py "$d/bash-os"
python3 tests/final-smoke.py "$d/bash-os"
python3 tests/gpu-smoke.py "$d/bash-os"
echo 'cross-smoke: exact selection, compression, nested execution and behavior fixtures passed'
