#!/usr/bin/env bash
# tests/wc-check.sh [BINARY] — wc builtin write-error contract vs GNU wc(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t wc 2>/dev/null) || t=
[[ $t == builtin ]] && ok "wc is a builtin with empty PATH" || no "type -t wc -> '$t'"

cd "$d"
printf 'one two  three\n\tfour\n' > ascii

got=$(B wc -l ascii)
if [[ -x /usr/bin/wc ]] && /usr/bin/wc --version 2>/dev/null | grep -q coreutils; then
  want=$(/usr/bin/wc -l ascii)
  [[ $got == "$want" ]] && ok "matches GNU wc -l" || no "builtin '$got' gnu '$want'"
  want=$(/usr/bin/wc -w ascii)
  got=$(B wc -w ascii)
  [[ $got == "$want" ]] && ok "matches GNU wc -w" || no "words builtin '$got' gnu '$want'"
  want=$(/usr/bin/wc -c ascii)
  got=$(B wc -c ascii)
  [[ $got == "$want" ]] && ok "matches GNU wc -c" || no "bytes builtin '$got' gnu '$want'"
else
  [[ $got == *2* ]] && ok "wc -l counts two lines" || no "wc -l '$got'"
fi

B wc ascii >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/wc ]]; then
  /usr/bin/wc ascii >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -q 'write error' "$d/gnu.err" \
    && ok "GNU wc also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B wc --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc"

echo "wc-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
