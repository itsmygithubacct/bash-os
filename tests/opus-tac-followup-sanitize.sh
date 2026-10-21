#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The production tac.c under ASan/UBSan, loaded into a built shell: the
# retained suites and the GNU regex/window/option suite. This compiles the
# module, so run it through the campaign build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
BX=$(realpath "${1:?usage: $0 BASH [CASES]}")
CASES=${2:-1500}
D=${BASHOS_TASK_DIR:?}/sanitize
mkdir -p "$D"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
"${CC:-cc}" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -fno-sanitize-recover=undefined -DHAVE_CONFIG_H -Iloadables/common -I"$BT" \
  -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" loadables/tac.c -o "$D/tac.so"
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport TAC_MODULE=%q\nexec %q "$@"\n' \
  "$("${CC:-cc}" -print-file-name=libasan.so)" "$D/tac.so" "$BX" > "$D/bash-tac"
chmod +x "$D/bash-tac"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1
python3 tests/tac-parity.py "$D/bash-tac"
python3 tests/sol-tac-parity.py "$D/bash-tac" --module "$D/tac.so"
python3 tests/opus-tac-followup-regex.py "$D/bash-tac" --module "$D/tac.so" --cases "$CASES"
python3 tests/grok-tac-fix-hang.py "$D/bash-tac" --module "$D/tac.so"
