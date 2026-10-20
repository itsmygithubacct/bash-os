#!/usr/bin/env bash
# Noncompiling native-shell checks. This script NEVER invokes rngseed load on
# an existing file, so no entropy-credit request can reach the host kernel.
set -euo pipefail
binary=$(realpath "${1:?native binary required}")
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
"$binary" --noprofile --norc -c '
  PATH=; export PATH
  type -t rngseed | { read -r kind; [[ $kind == builtin ]]; } || exit 1
  for ((i=0;i<5;i++)); do
    rngseed -- save "$1/seed" || exit 2
    rngseed load "$1/missing" || exit 3
  done
  rngseed >/dev/null 2>&1; [[ $? == 2 ]] || exit 4
  rngseed frob "$1/seed" >/dev/null 2>&1; [[ $? == 2 ]] || exit 5
  rngseed -x >/dev/null 2>&1; [[ $? == 2 ]] || exit 6
  rngseed save "$1/no-parent/seed" >/dev/null 2>&1; [[ $? == 1 ]] || exit 7
  rngseed load "$1/missing" 2>/dev/full; [[ $? == 1 ]] || exit 8
' rngseed-check "$dir"
python3 - "$dir" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p/'seed'
assert s.stat().st_size == 512 and s.stat().st_mode & 0o7777 == 0o600
assert list(p.iterdir()) == [s]
print('native rngseed: empty PATH, repeated saves/first boot, invalid input, output failure: pass')
PY
