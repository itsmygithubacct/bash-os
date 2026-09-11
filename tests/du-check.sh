#!/usr/bin/env bash
# tests/du-check.sh [BINARY] — du write errors must fail like du(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t du 2>/dev/null) || t=
[[ $t == builtin ]] && ok "du is a builtin with empty PATH" || no "type -t du -> '$t'"

printf abc > "$d/file"
B du -b "$d/file" >/dev/full 2>"$d/err"; rc=$?
if [[ $rc != 0 ]]; then
  ok "du -b file > /dev/full fails"
else
  no "du write-error rc=$rc err=$(cat "$d/err")"
fi
if [[ -x /usr/bin/du ]]; then
  /usr/bin/du -b "$d/file" >/dev/full 2>"$d/gerr"; grc=$?
  [[ $grc != 0 ]] && ok "GNU du > /dev/full fails" || no "GNU rc=$grc"
fi

echo "du-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
