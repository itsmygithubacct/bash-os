#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Instrument process wrappers and read-only device fixture paths.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic
  -fsanitize=address,undefined,float-cast-overflow -DHAVE_CONFIG_H
  -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables"
  -Iloadables/common)
: > "$d/load.sh"
for name in flock setsid ionice taskset chrt prlimit nice nohup timeout renice uclampset dmesg blkid lsblk losetup signal sysctl; do
  shim=()
  case "$name" in
    nice|nohup|blkid|lsblk)
      cat > "$d/$name-entry.c" <<EOF
#include <config.h>
#include "loadables.h"
extern int ${name}_builtin (WORD_LIST *);
extern char *${name}_doc[];
struct builtin ${name}_struct = {
  "$name", ${name}_builtin, BUILTIN_ENABLED, ${name}_doc, "$name", 0
};
EOF
      shim=("$d/$name-entry.c") ;;
  esac
  "$CC" "${flags[@]}" "loadables/$name.c" "${shim[@]}" -o "$d/$name.so"
  printf 'enable -f %q %q || exit\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
printf '#!/bin/bash\nexport LD_PRELOAD=%q${LD_PRELOAD:+:$LD_PRELOAD}\nexport BASH_ENV=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/load.sh" \
  "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86
for suite in process-wrapper-state process-numeric device-fixtures signal-lookup sysctl-readonly dmesg-fixture; do
  python3 "tests/$suite.py" "$d/bash-os"
done
bash tests/timeout-check.sh "$d/bash-os"
