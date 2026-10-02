#!/usr/bin/env bash
# Run Debian parity and install regression checks with instrumented modules.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
compile_flags=(-O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined
  -DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include"
  -I"$BT/builtins" -I"$BT/examples/loadables")
printf 'set -e\n' > "$d/load.sh"
for name in cp mv tr date coreutils; do
  shim=()
  if [[ $name != coreutils ]]; then
    # These sources export bashNAME_struct; enable -f NAME needs NAME_struct.
    cat > "$d/$name-entry.c" <<EOF
#include <config.h>
#include "loadables.h"
extern int ${name}_builtin (WORD_LIST *);
extern char *${name}_doc[];
struct builtin ${name}_struct = {
  "$name", ${name}_builtin, BUILTIN_ENABLED, ${name}_doc, "$name", 0
};
EOF
    shim=("$d/$name-entry.c")
  fi
  "$CC" "${compile_flags[@]}" \
    "loadables/$name.c" "${shim[@]}" -lm -o "$d/$name.so"
  printf 'enable -f %q %q\n' "$d/$name.so" "$name" >> "$d/load.sh"
done
# Only the builtin subprocess loads ASan; Debian's reference stays ordinary.
printf '#!/bin/bash\nexport LD_PRELOAD=%q\nexport BASH_ENV=%q\nexec %q "$@"\n' \
  "$("$CC" -print-file-name=libasan.so)" "$d/load.sh" \
  "$(realpath "${1:-out/bash}")" > "$d/bash-os"
chmod +x "$d/bash-os"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
# Keep sanitizer failures distinct from commands' expected rejection status 1.
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86
python3 tests/debian-parity.py "$d/bash-os"
python3 tests/coreutils-fastpaths.py "$d/bash-os"
python3 tests/install-truncate.py "$d/bash-os"
# Exercise the static glibc account-file lookup branch under instrumentation
# too, without loading NSS plugins into a statically linked process.
"$CC" "${compile_flags[@]}" -DBASHOS_STATIC=1 loadables/coreutils.c -lm -o "$d/coreutils.so"
python3 tests/debian-parity.py "$d/bash-os" -k install
