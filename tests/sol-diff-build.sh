#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build only: invoke through the build gate, then run Python tests separately.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=$(realpath -m "$1")
binary=$(realpath "$2")
mkdir -p "$dest"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
inc=(-DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins"
     -I"$BT/examples/loadables" -Iloadables/common)
for mode in native sanitize; do
  flags=(-O2)
  if [[ $mode == sanitize ]]; then flags=(-O1 -g -fsanitize=address,undefined); fi
  "${CC:-cc}" "${flags[@]}" -fPIC -shared -Wl,-Bsymbolic "${inc[@]}" \
    tests/sol-diff-alloc.c -o "$dest/diff-$mode.so"
  printf 'enable -f %q diff || exit\n' "$dest/diff-$mode.so" > "$dest/load-$mode.sh"
  {
    printf '#!/bin/bash\n'
    if [[ $mode == sanitize ]]; then
      printf 'export LD_PRELOAD=%q\n' "$("${CC:-cc}" -print-file-name=libasan.so)"
      printf 'export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:allocator_may_return_null=1\n'
      printf 'export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86\n'
      printf 'export BASHOS_TEST_SANITIZED=1\n'
    fi
    printf 'export BASH_ENV=%q\nexec %q "$@"\n' "$dest/load-$mode.sh" "$binary"
  } > "$dest/bash-$mode"
  chmod +x "$dest/bash-$mode"
done
if [[ $# -ge 3 ]]; then
  before=$(realpath "$3")
  "${CC:-cc}" -O2 -fPIC -shared -Wl,-Bsymbolic "${inc[@]}" \
    "-DSOL_DIFF_SOURCE=\"$before\"" tests/sol-diff-alloc.c -o "$dest/diff-before.so"
fi
