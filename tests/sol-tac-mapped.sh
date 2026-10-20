#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Preserve the tac assertions from shared suites without requiring unrelated
# formatting tools in this task's targeted build. Original scripts are read
# unchanged; their command definitions and fixture/reset logic are retained.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(realpath "${1:-$HERE/out/bash-sol-tac}")
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
python3 - "$HERE" "$D" <<'PY'
from pathlib import Path
import sys
root, out = map(Path, sys.argv[1:])
s = (root/'tests/text-tools-parity.sh').read_text()
# Keep setup, comparison function, all three original tac calls and summary.
a=s.index('echo "== byte-compared')
b=s.index('echo; echo "text-tools-parity:')
s=s[:a]+'\n'.join(l for l in s[a:b].splitlines() if l.startswith('cmp2 "tac'))+'\n'+s[b:]
(out/'text-tools.sh').write_text(s)
s=(root/'tests/repeat-input-check.sh').read_text()
a=s.index('# The four loadables')
s=s[:a]+'''check "control tac" A tac
check_second "control tac" tac
echo "repeat-input tac: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
'''
(out/'repeat.sh').write_text(s)
PY
bash "$D/text-tools.sh" "$BX"
bash "$D/repeat.sh" "$BX"
