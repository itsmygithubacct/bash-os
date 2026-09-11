#!/usr/bin/env bash
# tests/col-check.sh [BINARY] — col builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "col-check: missing binary $BX"; exit 1; }
command -v /usr/bin/col >/dev/null || { echo "col-check: SKIP (no host col)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t col 2>/dev/null) || t=
[[ $t == builtin ]] && ok "col is a builtin with empty PATH" || no "type -t col -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/col -b < "$d/input" > "$d/once"
{ /usr/bin/col -b < "$d/input"; /usr/bin/col -b < "$d/input"; /usr/bin/col -b < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU col -b emits three copies" \
  || no "GNU col -b did not emit three copies"
"$BX" -c 'PATH=; col -b < "$1"; col -b < "$1"; col -b < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh col -b redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

echo "col-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
