#!/usr/bin/env bash
# tests/comm-check.sh [BINARY] — comm builtin against GNU comm(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"; kill $(jobs -p) 2>/dev/null' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t comm 2>/dev/null) || t=
[[ $t == builtin ]] && ok "comm is a builtin with empty PATH" || no "type -t comm -> '$t'"

cd "$d"
printf 'a\nb\nc\n' > left
printf 'b\nc\nd\n' > right
: > empty

got=$(B comm left right)
want=$(printf 'a\n\t\tb\n\t\tc\n\td\n')
[[ $got == "$want" ]] && ok "three-column comm" || no "comm '$got'"

if [[ -x /usr/bin/comm ]]; then
  g=$(/usr/bin/comm left right)
  b=$(B comm left right)
  [[ $b == "$g" ]] && ok "matches GNU comm" || no "builtin '$b' gnu '$g'"
  g=$(/usr/bin/comm -12 left right)
  b=$(B comm -12 left right)
  [[ $b == "$g" ]] && ok "matches GNU comm -12" || no "builtin -12 '$b' gnu '$g'"
fi

B comm left right >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/comm ]]; then
  /usr/bin/comm left right >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -q 'write error' "$d/gnu.err" \
    && ok "GNU comm also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B comm - - </dev/null >/dev/null 2>"$d/both"; rc=$?
[[ $rc != 0 && -s $d/both ]] && ok "both files as stdin fail" || no "both-stdin rc=$rc err=$(cat "$d/both")"

B comm left >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 && -s $d/miss ]] && ok "missing operand fails" || no "missing rc=$rc"

B comm left right extra >/dev/null 2>"$d/extra"; rc=$?
[[ $rc != 0 && -s $d/extra ]] && ok "extra operand fails" || no "extra rc=$rc"

mkfifo "$d/h"
{ head -c 65536 /dev/zero | tr '\0' a; printf '\n'; sleep 10; } >"$d/h" &
wp=$!
timeout 2 "$BX" -c 'PATH=; comm - empty >/dev/full' <"$d/h" 2>"$d/h.err"
rc=$?
kill $wp 2>/dev/null; wait $wp 2>/dev/null || true
if [[ $rc != 0 && $rc != 124 ]] && grep -q 'write error' "$d/h.err"; then
  ok "held producer stops on write failure (rc=$rc)"
else
  no "held rc=$rc err=$(tr '\n' ' ' <"$d/h.err")"
fi

echo "comm-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
