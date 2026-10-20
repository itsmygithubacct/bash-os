#!/usr/bin/env bash
# tests/opus-ts-sanitize.sh [BINARY] — ASan/UBSan (and LeakSanitizer) run of
# tests/opus-ts-highlight.py and the final-smoke parsing group, with ts, hl and
# nano plus the vendored tree-sitter runtime and grammars instrumented in one
# shared object loaded over the builtins of BINARY. Compiles; run it through
# the build gate.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
names=(ts hl nano)
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" "${names[@]}"
sources=("$d/helpers/builtins/"*.c)
for name in "${names[@]}"; do sources+=("loadables/$name.c"); done
flags=(-O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$BT" -I"$BT/include" -I"$d/helpers/builtins" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
for source in "${sources[@]}"; do
  "$CC" "${flags[@]}" -c "$source" -o "$d/objects/$(basename "${source%.c}").o"
done
"$CC" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o \
  -lm -ldl -lpthread -o "$d/ts.so"
target=$(realpath "${1:-out/bash}")
# No `set -e` here: the tests run failing commands on purpose without it.
printf '[[ $BASH == %q ]] || return 0\n' "$target" > "$d/load.sh"
for name in "${names[@]}"; do printf 'enable -f %q %q || exit 99\n' "$d/ts.so" "$name" >> "$d/load.sh"; done
# Only allocations made by the instrumented objects can be attributed; the
# uninstrumented shell's own process-lifetime allocations are not ours.
printf 'leak:^xmalloc$\nleak:^sh_xmalloc$\nleak:^xrealloc$\nleak:^sh_xrealloc$\n' > "$d/lsan.supp"
TS_LOAD_ENV="$d/load.sh" TS_ASAN_LIB=$("$CC" -print-file-name=libasan.so) TS_LSAN_SUPP="$d/lsan.supp" \
  python3 tests/opus-ts-highlight.py "$target"
FINAL_LOAD_ENV="$d/load.sh" FINAL_ASAN_LIB=$("$CC" -print-file-name=libasan.so) \
  python3 tests/final-smoke.py "$target" parsing
