#!/usr/bin/env bash
# tests/diff-check.sh [BINARY] — final-newline-only difference must differ
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t diff 2>/dev/null) || t=
[[ $t == builtin ]] && ok "diff is a builtin with empty PATH" || no "type -t diff -> '$t'"

printf 'a' > "$d/input"
printf 'a\n' > "$d/input-newline"
B diff "$d/input" "$d/input-newline" >/dev/null 2>"$d/err"; rc=$?
if [[ $rc != 0 ]]; then
  ok "diff reports files that differ only in the final newline"
else
  no "diff equal rc=$rc err=$(cat "$d/err")"
fi
if [[ -x /usr/bin/diff ]]; then
  /usr/bin/diff "$d/input" "$d/input-newline" >/dev/null 2>"$d/gerr"; grc=$?
  [[ $grc != 0 ]] && ok "GNU diff also reports the newline difference" || no "GNU rc=$grc"
fi

echo "diff-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
