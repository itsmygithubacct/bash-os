#!/usr/bin/env bash
# tests/colrm-check.sh [BINARY] — colrm builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "colrm-check: missing binary $BX"; exit 1; }
command -v /usr/bin/colrm >/dev/null || { echo "colrm-check: SKIP (no host colrm)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t colrm 2>/dev/null) || t=
[[ $t == builtin ]] && ok "colrm is a builtin with empty PATH" || no "type -t colrm -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/colrm 4 < "$d/input" > "$d/once"
{ /usr/bin/colrm 4 < "$d/input"; /usr/bin/colrm 4 < "$d/input"; /usr/bin/colrm 4 < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU colrm 4 emits three copies" \
  || no "GNU colrm 4 did not emit three copies"
"$BX" -c 'PATH=; colrm 4 < "$1"; colrm 4 < "$1"; colrm 4 < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh colrm 4 redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

echo "colrm-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
