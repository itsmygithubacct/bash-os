#!/usr/bin/env bash
# tests/hexdump-check.sh [BINARY] — hexdump builtin: repeated redirected stdin
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1readers}")
[[ -x $BX ]] || { echo "hexdump-check: missing binary $BX"; exit 1; }
command -v /usr/bin/hexdump >/dev/null || { echo "hexdump-check: SKIP (no host hexdump)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t hexdump 2>/dev/null) || t=
[[ $t == builtin ]] && ok "hexdump is a builtin with empty PATH" || no "type -t hexdump -> '$t'"

printf 'alpha\nbeta\n' > "$d/input"
/usr/bin/hexdump -C < "$d/input" > "$d/once"
{ /usr/bin/hexdump -C < "$d/input"; /usr/bin/hexdump -C < "$d/input"; /usr/bin/hexdump -C < "$d/input"; } > "$d/gnu"
cat "$d/once" "$d/once" "$d/once" > "$d/want"
cmp -s "$d/gnu" "$d/want" && ok "GNU hexdump -C emits three copies" \
  || no "GNU hexdump -C did not emit three copies"
"$BX" -c 'PATH=; hexdump -C < "$1"; hexdump -C < "$1"; hexdump -C < "$1"' _ "$d/input" > "$d/got"
cmp -s "$d/got" "$d/gnu" && ok "three fresh hexdump -C redirections match GNU" \
  || no "repeat-input got $(od -An -tx1 "$d/got" | tr -s ' ') want $(od -An -tx1 "$d/gnu" | tr -s ' ')"

echo "hexdump-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
