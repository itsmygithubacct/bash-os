#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# tests/opus-uclampset-sanitize.sh [BINARY] — run tests/opus-uclampset.py
# against uclampset built as an ASan/UBSan loadable. Compiles; run it through
# the campaign build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; [[ -n ${UCLAMP_SANITIZE_DEBUG:-} ]] && trap - EXIT && echo "$d"
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -Wall -Wextra \
  -fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=undefined \
  -DHAVE_CONFIG_H -U_FORTIFY_SOURCE -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" \
  -Iloadables/common loadables/uclampset.c -o "$d/uclampset.so"
printf 'enable -f %q uclampset || exit\n' "$d/uclampset.so" > "$d/load.sh"
printf '#!/bin/bash\nexport LD_PRELOAD=%q${LD_PRELOAD:+:$LD_PRELOAD}\nexport BASH_ENV=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/load.sh" \
  "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86
# The instrumented object, not the compiled-in builtin, must be the one tested.
"$d/bash-os" -c 'mapfile -t m < /proc/$$/maps; [[ "${m[*]}" == */uclampset.so* ]]' \
  || { echo "opus-uclampset-sanitize: instrumented loadable not mapped" >&2; exit 1; }
python3 tests/opus-uclampset.py "$d/bash-os"
echo "opus-uclampset-sanitize: ok"
