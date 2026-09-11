#!/usr/bin/env bash
# tests/ar-check.sh [BINARY] — truncated archive must be rejected
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t ar 2>/dev/null) || t=
[[ $t == builtin ]] && ok "ar is a builtin with empty PATH" || no "type -t ar -> '$t'"

printf '%s' '!<arch>
X' > "$d/partial.a"
B ar t "$d/partial.a" >/dev/null 2>"$d/err"; rc=$?
if [[ $rc != 0 ]]; then
  ok "ar t partial.a fails"
else
  no "ar truncated header rc=$rc err=$(cat "$d/err")"
fi
if [[ -x /usr/bin/ar ]]; then
  /usr/bin/ar t "$d/partial.a" >/dev/null 2>"$d/gerr"; grc=$?
  [[ $grc != 0 ]] && ok "GNU ar t partial.a fails" || no "GNU rc=$grc"
fi

echo "ar-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
