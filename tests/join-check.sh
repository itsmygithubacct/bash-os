#!/usr/bin/env bash
# tests/join-check.sh [BINARY] — join builtin against GNU join(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"; kill $(jobs -p) 2>/dev/null' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t join 2>/dev/null) || t=
[[ $t == builtin ]] && ok "join is a builtin with empty PATH" || no "type -t join -> '$t'"

cd "$d"
printf '1 a\n2 b\n3 c\n' > left
printf '1 A\n2 B\n4 D\n' > right
: > empty

got=$(B join left right)
want=$'1 a A\n2 b B'
[[ $got == "$want" ]] && ok "inner join" || no "inner join '$got'"

got=$(B join -a 1 left right)
want=$'1 a A\n2 b B\n3 c'
[[ $got == "$want" ]] && ok "join -a1" || no "join -a1 '$got'"

if [[ -x /usr/bin/join ]]; then
  g=$(/usr/bin/join left right)
  b=$(B join left right)
  [[ $b == "$g" ]] && ok "matches GNU join" || no "builtin '$b' gnu '$g'"
  g=$(/usr/bin/join -a 1 left right)
  b=$(B join -a 1 left right)
  [[ $b == "$g" ]] && ok "matches GNU join -a1" || no "builtin -a1 '$b' gnu '$g'"
fi

B join left right >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/join ]]; then
  /usr/bin/join left right >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -q 'write error' "$d/gnu.err" \
    && ok "GNU join also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B join - - </dev/null >/dev/null 2>"$d/both"; rc=$?
[[ $rc != 0 ]] && grep -q 'standard input' "$d/both" \
  && ok "both files as stdin fail" || no "both-stdin rc=$rc err=$(cat "$d/both")"

B join left >/dev/null 2>"$d/miss"; rc=$?
[[ $rc != 0 && -s $d/miss ]] && ok "missing operand fails" || no "missing rc=$rc"

B join left right extra >/dev/null 2>"$d/extra"; rc=$?
[[ $rc != 0 && -s $d/extra ]] && ok "extra operand fails" || no "extra rc=$rc"

# A 64 KiB unmatched record fills stdio and fails the write. GNU then leaves
# without reading again; holding the producer open must not hang.
held(){
  local label=$1 extra=$2
  mkfifo "$d/h"
  { head -c 65536 /dev/zero | tr '\0' a; printf '\n'; sleep 10; } >"$d/h" &
  local wp=$!
  timeout 2 "$BX" -c "PATH=; join $extra >/dev/full" <"$d/h" 2>"$d/h.err"
  local rc=$?
  kill $wp 2>/dev/null; wait $wp 2>/dev/null || true
  rm -f "$d/h"
  if [[ $rc != 0 && $rc != 124 ]] && grep -q 'write error' "$d/h.err"; then
    ok "$label stops on write failure (rc=$rc)"
  else
    no "$label rc=$rc err=$(tr '\n' ' ' <"$d/h.err")"
  fi
}
held "unmatched -a1" "--nocheck-order -a1 - empty"
held "unmatched -a2" "--nocheck-order -a2 empty -"
held "header" "--header --nocheck-order - empty"

echo "join-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
