#!/usr/bin/env bash
# Run full behavior fixtures through QEMU. Guest exec needs binfmt support.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
binary=$(realpath "${1:?usage: tests/cross-smoke.sh BINARY}")
runner=$(command -v "${QEMU_RISCV64:-qemu-riscv64}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
printf '#!/bin/bash\nexec %q %q "$@"\n' "$runner" "$binary" > "$d/bash-os"
chmod +x "$d/bash-os"
# nano selftest-highlight measured 189s under QEMU AArch64 versus 13s native
# on a loaded host. 20x gives each final-smoke guest command 600s, over 3x
# that measured emulated time, without changing any fixture or native limit.
export BASH_OS_TIMEOUT_SCALE=${BASH_OS_TIMEOUT_SCALE:-20}
run_group() {
  local group=$1; shift
  local TIMEFORMAT="cross-smoke/$group: %3R seconds"
  time "$@"
}
# qemu-user before 9.0 answers prctl(PR_SET_CHILD_SUBREAPER) with EINVAL (its
# linux-user layer lists the option as TODO), and the ptybroker backend under
# screen sessions must become a subreaper. Kernels have provided it since 3.4,
# so only the screen session checks are skipped, and only on such an emulator.
qemu_version=$("$runner" --version | sed -n '1s/.* version \([0-9][0-9.]*\).*/\1/p')
if [[ -n $qemu_version ]] && (( ${qemu_version%%.*} < 9 )); then
  export BASH_OS_NO_SUBREAPER="qemu-user $qemu_version does not emulate prctl(PR_SET_CHILD_SUBREAPER), which ptybroker requires"
fi
BASH_OS_RUNNER="$runner" run_group profile python3 tests/profile-smoke.py "$binary"
run_group compression-nested "$d/bash-os" -e -o pipefail -c '
  PATH=
  [[ $(printf "compression fixture" | zstd -c - | zstd -dc -) == "compression fixture" ]]
  "$BASH" -c "[[ 2+3 -eq 5 ]]"
'
run_group tac-parity python3 tests/tac-parity.py "$d/bash-os"
run_group input-lifetime python3 tests/input-lifetime.py "$d/bash-os"
run_group helper-smoke python3 tests/helper-smoke.py "$d/bash-os"
run_group final-smoke python3 tests/final-smoke.py "$d/bash-os"
run_group gpu-smoke python3 tests/gpu-smoke.py "$d/bash-os"
# The git builtin on the emulated machine, held against the real git on
# this one: a repository written there must read the same way here.
run_group git-parity python3 tests/git-parity.py "$d/bash-os" basic-commit branches
echo 'cross-smoke: exact selection, compression, nested execution and behavior fixtures passed'
