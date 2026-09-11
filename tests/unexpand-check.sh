#!/usr/bin/env bash
# tests/unexpand-check.sh [BINARY] — unexpand builtin against GNU unexpand(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"; kill $(jobs -p) 2>/dev/null' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t unexpand 2>/dev/null) || t=
[[ $t == builtin ]] && ok "unexpand is a builtin with empty PATH" || no "type -t unexpand -> '$t'"

cd "$d"
printf 'a\tb\tc\nxx\tyy\tzz\n        eight\n' > tabs.txt

got=$(B unexpand -a tabs.txt)
if [[ -x /usr/bin/unexpand ]]; then
  want=$(/usr/bin/unexpand -a tabs.txt)
  [[ $got == "$want" ]] && ok "matches GNU unexpand -a" || no "builtin '$got' gnu '$want'"
  want=$(/usr/bin/unexpand tabs.txt)
  got=$(B unexpand tabs.txt)
  [[ $got == "$want" ]] && ok "matches GNU unexpand leading" || no "leading builtin '$got' gnu '$want'"
else
  [[ -n $got ]] && ok "unexpand -a produced output" || no "unexpand -a empty"
fi

B unexpand -a tabs.txt >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/unexpand ]]; then
  /usr/bin/unexpand -a tabs.txt >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -q 'write error' "$d/gnu.err" \
    && ok "GNU unexpand also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B unexpand --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc"

mkfifo "$d/h"
{ head -c 65536 /dev/zero | tr '\0' a; printf '\n'; sleep 10; } >"$d/h" &
wp=$!
timeout 2 "$BX" -c 'PATH=; unexpand -a >/dev/full' <"$d/h" 2>"$d/h.err"
rc=$?
kill $wp 2>/dev/null; wait $wp 2>/dev/null || true
if [[ $rc != 0 && $rc != 124 ]] && grep -q 'write error' "$d/h.err"; then
  ok "held producer stops on write failure (rc=$rc)"
else
  no "held rc=$rc err=$(tr '\n' ' ' <"$d/h.err")"
fi

echo "unexpand-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
