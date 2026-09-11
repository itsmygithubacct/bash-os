#!/usr/bin/env bash
# tests/rev-check.sh [BINARY] — rev builtin against rev(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t rev 2>/dev/null) || t=
[[ $t == builtin ]] && ok "rev is a builtin with empty PATH" || no "type -t rev -> '$t'"

cd "$d"
printf 'abc\n12345\n' > in.txt
printf 'no newline' > nonl.txt

got=$(B rev in.txt)
want=$'cba\n54321'
[[ $got == "$want" ]] && ok "reverses each line" || no "rev '$got'"

got=$(B rev nonl.txt)
[[ $got == 'enilwen on' ]] && ok "line without newline" || no "nonl '$got'"

if [[ -x /usr/bin/rev ]]; then
  g=$(/usr/bin/rev in.txt)
  b=$(B rev in.txt)
  [[ $b == "$g" ]] && ok "matches rev(1)" || no "builtin '$b' gnu '$g'"
  g=$(/usr/bin/rev nonl.txt)
  b=$(B rev nonl.txt)
  [[ $b == "$g" ]] && ok "matches rev(1) with no final newline" || no "nonl builtin '$b' gnu '$g'"
fi

B rev in.txt >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/rev ]]; then
  /usr/bin/rev in.txt >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -q 'write error' "$d/gnu.err" \
    && ok "rev(1) also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B rev --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc"

B rev missing >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 && -s $d/miss ]] && ok "missing file fails with a diagnostic" || no "missing rc=$rc err=$(cat "$d/miss")"

echo "rev-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
