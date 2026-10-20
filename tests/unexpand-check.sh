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

B unexpand -a tabs.txt > builtin.out; brc=$?
if [[ -x /usr/bin/unexpand ]]; then
  /usr/bin/unexpand -a tabs.txt > gnu.out; grc=$?
  [[ $brc == "$grc" ]] && cmp -s builtin.out gnu.out \
    && ok "matches GNU unexpand -a" || no "unexpand -a bytes/status differ"
  /usr/bin/unexpand tabs.txt > gnu.out; grc=$?
  B unexpand tabs.txt > builtin.out; brc=$?
  [[ $brc == "$grc" ]] && cmp -s builtin.out gnu.out \
    && ok "matches GNU unexpand leading" || no "leading bytes/status differ"
else
  [[ $brc == 0 && -s builtin.out ]] && ok "unexpand -a produced output" || no "unexpand -a failed/empty"
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
