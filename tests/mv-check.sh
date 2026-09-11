#!/usr/bin/env bash
# tests/mv-check.sh [BINARY] — mv same-file must fail like mv(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t mv 2>/dev/null) || t=
[[ $t == builtin ]] && ok "mv is a builtin with empty PATH" || no "type -t mv -> '$t'"

printf abc > "$d/file"
B mv "$d/file" "$d/file" >/dev/null 2>"$d/err"; rc=$?
got=$(cat "$d/file")
if [[ $rc != 0 && $got == abc ]]; then
  ok "mv file file fails and preserves bytes"
else
  no "mv same-file rc=$rc contents='$got' err=$(cat "$d/err")"
fi
if [[ -x /usr/bin/mv ]]; then
  printf abc > "$d/gfile"
  /usr/bin/mv "$d/gfile" "$d/gfile" >/dev/null 2>"$d/gerr"; grc=$?
  [[ $grc != 0 && $(cat "$d/gfile") == abc ]] && ok "GNU mv file file also fails" || no "GNU rc=$grc"
fi

echo "mv-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
