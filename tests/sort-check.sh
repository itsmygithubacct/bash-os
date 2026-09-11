#!/usr/bin/env bash
# tests/sort-check.sh [BINARY] — sort builtin write-error contract vs GNU sort(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t sort 2>/dev/null) || t=
[[ $t == builtin ]] && ok "sort is a builtin with empty PATH" || no "type -t sort -> '$t'"

cd "$d"
printf 'c\na\nb\n' > in.txt

got=$(B sort in.txt)
want=$'a\nb\nc'
[[ $got == "$want" ]] && ok "sorts lines" || no "sort '$got'"

if [[ -x /usr/bin/sort ]] && /usr/bin/sort --version 2>/dev/null | grep -q coreutils; then
  g=$(LC_ALL=C /usr/bin/sort in.txt)
  b=$(LC_ALL=C B sort in.txt)
  [[ $b == "$g" ]] && ok "matches GNU sort" || no "builtin '$b' gnu '$g'"
  g=$(LC_ALL=C /usr/bin/sort -n <<'EOF'
10
2
1
EOF
)
  b=$(printf '10\n2\n1\n' | LC_ALL=C "$BX" -c 'PATH=; sort -n')
  [[ $b == "$g" ]] && ok "matches GNU sort -n" || no "numeric builtin '$b' gnu '$g'"
fi

B sort in.txt >/dev/full 2>"$d/err"; rc=$?
[[ $rc != 0 ]] && grep -q 'write error' "$d/err" \
  && ok "write to /dev/full fails with a diagnostic" \
  || no "full rc=$rc err=$(cat "$d/err")"

if [[ -x /usr/bin/sort ]]; then
  /usr/bin/sort in.txt >/dev/full 2>"$d/gnu.err"; grc=$?
  [[ $grc != 0 ]] && grep -qi 'write error' "$d/gnu.err" \
    && ok "GNU sort also fails on /dev/full" \
    || no "GNU full rc=$grc err=$(cat "$d/gnu.err")"
fi

B sort --help >"$d/help" 2>&1; rc=$?
[[ $rc == 0 && -s $d/help ]] && ok "--help exits 0 with usage" || no "--help rc=$rc"

echo "sort-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
