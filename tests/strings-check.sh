#!/usr/bin/env bash
# tests/strings-check.sh [BINARY] — strings builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "strings-check: missing binary $BX"; exit 1; }
command -v /usr/bin/strings >/dev/null || { echo "strings-check: SKIP (no host strings)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t strings 2>/dev/null) || t=
[[ $t == builtin ]] && ok "strings is a builtin with empty PATH" || no "type -t strings -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/strings < "$d/input" > "$d/once"
{ /usr/bin/strings < "$d/input"; /usr/bin/strings < "$d/input"; /usr/bin/strings < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU strings emits three copies" \
  || no "GNU strings did not emit three copies"
"$BX" -c 'PATH=; strings < "$1"; strings < "$1"; strings < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh strings redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

echo "strings-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
