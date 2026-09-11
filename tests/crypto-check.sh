#!/usr/bin/env bash
# tests/crypto-check.sh [BINARY] — failed digest write must fail
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

t=$("$BX" -c 'PATH=; type -t crypto' 2>/dev/null) || t=
[[ $t == builtin ]] && ok "crypto is a builtin with empty PATH" || no "type -t crypto -> '$t'"

printf a > "$d/in"
"$BX" -c 'PATH=; crypto sha256 -x' <"$d/in" >/dev/full 2>"$d/err"; rc=$?
if [[ $rc != 0 ]]; then
  ok "crypto sha256 -x > /dev/full fails"
else
  no "crypto write-error rc=$rc err=$(cat "$d/err")"
fi
if [[ -x /usr/bin/sha256sum ]]; then
  /usr/bin/sha256sum <"$d/in" >/dev/full 2>"$d/gerr"; grc=$?
  [[ $grc != 0 ]] && ok "GNU sha256sum > /dev/full fails" || no "GNU rc=$grc"
fi

echo "crypto-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
