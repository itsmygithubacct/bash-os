#!/usr/bin/env bash
# tests/column-check.sh [BINARY] — column builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "column-check: missing binary $BX"; exit 1; }
command -v /usr/bin/column >/dev/null || { echo "column-check: SKIP (no host column)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t column 2>/dev/null) || t=
[[ $t == builtin ]] && ok "column is a builtin with empty PATH" || no "type -t column -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/column -t < "$d/input" > "$d/once"
{ /usr/bin/column -t < "$d/input"; /usr/bin/column -t < "$d/input"; /usr/bin/column -t < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU column -t emits three copies" \
  || no "GNU column -t did not emit three copies"
"$BX" -c 'PATH=; column -t < "$1"; column -t < "$1"; column -t < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh column -t redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

echo "column-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
