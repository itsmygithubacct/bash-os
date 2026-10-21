#!/usr/bin/env bash
# Build nano and its ts companion with ASan/UBSan as loadable objects, load
# them into the tested shell, and run every nano selftest and both PTY suites.
# Usage: tests/opus-nano-sanitize.sh [BASH-OS-BINARY]
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
names=(nano ts)
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables" "$d/objects"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" "${names[@]}"
flags=(-O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined -DHAVE_CONFIG_H
       -I"$BT" -I"$BT/include" -I"$d/helpers/builtins" -Iloadables/common
       -I"$BT/builtins" -I"$BT/examples/loadables")
for src in "$d/helpers/builtins/"*.c loadables/nano.c loadables/ts.c; do
  "$CC" "${flags[@]}" -c "$src" -o "$d/objects/$(basename "${src%.c}").o"
done
"$CC" -shared -Wl,-Bsymbolic -fsanitize=address,undefined "$d/objects/"*.o \
  -lm -ldl -lpthread -o "$d/nano.so"
target=$(realpath "${1:-out/bash}")
printf '[[ $BASH == %q ]] || return 0\nset -e\n' "$target" > "$d/load.sh"
for name in "${names[@]}"; do printf 'enable -f %q %q\n' "$d/nano.so" "$name" >> "$d/load.sh"; done
export BASH_ENV="$d/load.sh" LD_PRELOAD=$("$CC" -print-file-name=libasan.so)
printf 'leak:^xmalloc$\nleak:^sh_xmalloc$\nleak:^xrealloc$\nleak:^sh_xrealloc$\n' > "$d/lsan.supp"
export LSAN_OPTIONS="suppressions=$d/lsan.supp"
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
fail=0
for t in '' -piecetable -keybindings -saveprompt -replace -search -resize -statusbar \
         -yank-ring -atomic-save -undo-redo -justify -spell -complete -selection -linecache \
         -input -display; do
  out=$(env -i PATH= LANG=C.UTF-8 BASH_ENV="$BASH_ENV" LD_PRELOAD="$LD_PRELOAD" \
        ASAN_OPTIONS="$ASAN_OPTIONS" LSAN_OPTIONS="$LSAN_OPTIONS" UBSAN_OPTIONS="$UBSAN_OPTIONS" \
        "$target" -c "nano selftest$t" 2>&1) || { echo "FAIL selftest$t"; echo "$out" | tail -30; fail=1; continue; }
  if grep -q -E '^not ok|runtime error|AddressSanitizer' <<<"$out"; then
    echo "FAIL selftest$t"; echo "$out" | tail -30; fail=1
  else
    echo "ok selftest$t ($(tail -1 <<<"$out"))"
  fi
done
# Sessions under ASan are slower but the suite waits on frames, not delays.
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 tests/opus-nano-pty.py "$target" || fail=1
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 python3 tests/sol-nano-pty.py "$target" || fail=1
exit $fail
