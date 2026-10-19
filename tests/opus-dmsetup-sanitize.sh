#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# tests/opus-dmsetup-sanitize.sh [BASH] — run the dmsetup ioctl fixture suite
# with dmsetup rebuilt under ASan/UBSan and enabled over the shell's builtin.
# Compiles two shared objects: run it under the campaign build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic \
  -fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=undefined -DHAVE_CONFIG_H \
  -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" -Iloadables/common \
  loadables/dmsetup.c -o "$d/dmsetup.so"
"$CC" -std=gnu11 -O1 -g -fPIC -shared -o "$d/dmsfix.so" tests/opus-dmsetup-fixture.c -ldl
printf 'enable -f %q dmsetup || exit\n' "$d/dmsetup.so" > "$d/load.sh"
printf '#!/bin/bash\nexport LD_PRELOAD=%q${LD_PRELOAD:+:$LD_PRELOAD}\nexport BASH_ENV=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/load.sh" \
  "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86
"$d/bash-os" -c 'm=$(</proc/$$/maps); [[ $m == */dmsetup.so* ]]' || { echo "instrumented dmsetup.so not loaded" >&2; exit 1; }
DMSETUP_FIXTURE_SO="$d/dmsfix.so" python3 tests/opus-dmsetup-ioctl.py "$d/bash-os"
