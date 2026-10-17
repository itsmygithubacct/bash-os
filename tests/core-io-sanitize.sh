#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Instrument the core file/stream regressions without instrumenting GNU references.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
: > "$d/load.sh"
for name in cmp cp split diff dd; do
  shim=()
  case "$name" in
    cmp|cp|diff)
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
  # Do not leave errexit enabled: tests deliberately recover after failures.
  printf 'enable -f %q %q || exit\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport BASH_ENV=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/load.sh" \
  "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86
# The native suite exercises RLIMIT_AS; ASan reserves a huge virtual range.
export BASHOS_TEST_SANITIZED=1
for suite in cmp-streams cp-safety split-safety diff-safety dd-safety; do
  python3 "tests/$suite.py" "$d/bash-os"
done
