#!/usr/bin/env bash
# tests/csplit-check.sh [BINARY] — csplit builtin: repeated stdin vs GNU csplit(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1split}")
[[ -x $BX ]] || { echo "csplit-check: missing binary $BX"; exit 1; }
command -v /usr/bin/csplit >/dev/null || { echo "csplit-check: SKIP (no /usr/bin/csplit)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t csplit 2>/dev/null) || t=
[[ $t == builtin ]] && ok "csplit is a builtin with empty PATH" || no "type -t csplit -> '$t'"

printf 'alpha\nbeta\ngamma\n' > "$d/input"

# Named file is unaffected (control). Drive the shipped builtin via B().
mkdir -p "$d/named"
( cd "$d/named" && B csplit -s -f named- "$d/input" 2 )
[[ $(cat "$d/named/named-00") == alpha && $(cat "$d/named/named-01") == $'beta\ngamma' ]] \
  && ok "named-file csplit -s -f … 2" || no "named-file $(ls -A "$d/named" | tr '\n' ' ')"

# Published fixture: three fresh redirections in one shell.
# GNU: pieces/{1,2,3}-{00,01}. Catalog binary left 2-00 and 3-00 empty.
mkdir -p "$d/gnu/pieces" "$d/bos/pieces"
( cd "$d/gnu" && for i in 1 2 3; do /usr/bin/csplit -s -f "pieces/$i-" - 2 < "$d/input"; done )
( cd "$d/bos" && "$BX" -c 'PATH=; for i in 1 2 3; do csplit -s -f "pieces/$i-" - 2 < "$1" || exit; done' \
    _ "$d/input" >"$d/bos.out" 2>"$d/bos.err" )
rc=$?

gnu_names=$(cd "$d/gnu/pieces" && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')
bos_names=$(cd "$d/bos/pieces" && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')
[[ $gnu_names == '1-00 1-01 2-00 2-01 3-00 3-01 ' ]] \
  && ok "GNU csplit created six pieces" || no "GNU names '$gnu_names'"
[[ $bos_names == "$gnu_names" && $rc == 0 && ! -s $d/bos.out && ! -s $d/bos.err ]] \
  && ok "builtin created the same six pieces (rc=$rc)" \
  || no "builtin names '$bos_names' rc=$rc out=$(cat "$d/bos.out") err=$(cat "$d/bos.err")"

match=1
for f in 1-00 1-01 2-00 2-01 3-00 3-01; do
  if ! cmp -s "$d/gnu/pieces/$f" "$d/bos/pieces/$f"; then
    match=0
    no "GNU mismatch pieces/$f"
  fi
done
[[ $match == 1 ]] && ok "published fixture matches GNU file outputs"

[[ $(cat "$d/bos/pieces/1-00") == alpha ]] && ok "1-00 is alpha" || no "1-00 $(cat -A "$d/bos/pieces/1-00" 2>/dev/null)"
[[ $(cat "$d/bos/pieces/1-01") == $'beta\ngamma' ]] && ok "1-01 is beta/gamma" || no "1-01 $(cat -A "$d/bos/pieces/1-01" 2>/dev/null)"
[[ $(cat "$d/bos/pieces/3-00") == alpha && $(cat "$d/bos/pieces/3-01") == $'beta\ngamma' ]] \
  && ok "third invocation files are not empty" || no "third invocation missing content"

echo "csplit-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
