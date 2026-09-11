#!/usr/bin/env bash
# tests/split-check.sh [BINARY] — split builtin: repeated stdin vs GNU split(1)
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash-p1split}")
[[ -x $BX ]] || { echo "split-check: missing binary $BX"; exit 1; }
command -v /usr/bin/split >/dev/null || { echo "split-check: SKIP (no /usr/bin/split)"; exit 0; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }

t=$(B type -t split 2>/dev/null) || t=
[[ $t == builtin ]] && ok "split is a builtin with empty PATH" || no "type -t split -> '$t'"

printf 'alpha\nbeta\ngamma\n' > "$d/input"

# Named file is unaffected (control). Drive the shipped builtin via B().
mkdir -p "$d/named"
( cd "$d/named" && B split -l 2 "$d/input" named- )
[[ $(cat "$d/named/named-aa") == $'alpha\nbeta' && $(cat "$d/named/named-ab") == gamma ]] \
  && ok "named-file split -l 2" || no "named-file $(ls -A "$d/named" | tr '\n' ' ')"

# Published fixture: three fresh redirections in one shell.
# GNU: pieces/{1,2,3}-{aa,ab}. Catalog binary only created 1-aa and 1-ab.
mkdir -p "$d/gnu/pieces" "$d/bos/pieces"
( cd "$d/gnu" && for i in 1 2 3; do /usr/bin/split -l 2 - "pieces/$i-" < "$d/input"; done )
( cd "$d/bos" && "$BX" -c 'PATH=; for i in 1 2 3; do split -l 2 - "pieces/$i-" < "$1" || exit; done' \
    _ "$d/input" >"$d/bos.out" 2>"$d/bos.err" )
rc=$?

gnu_names=$(cd "$d/gnu/pieces" && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')
bos_names=$(cd "$d/bos/pieces" && find . -type f | sed 's|^\./||' | sort | tr '\n' ' ')
[[ $gnu_names == '1-aa 1-ab 2-aa 2-ab 3-aa 3-ab ' ]] \
  && ok "GNU split created six pieces" || no "GNU names '$gnu_names'"
[[ $bos_names == "$gnu_names" && $rc == 0 && ! -s $d/bos.out && ! -s $d/bos.err ]] \
  && ok "builtin created the same six pieces (rc=$rc)" \
  || no "builtin names '$bos_names' rc=$rc out=$(cat "$d/bos.out") err=$(cat "$d/bos.err")"

match=1
for f in 1-aa 1-ab 2-aa 2-ab 3-aa 3-ab; do
  if ! cmp -s "$d/gnu/pieces/$f" "$d/bos/pieces/$f"; then
    match=0
    no "GNU mismatch pieces/$f"
  fi
done
[[ $match == 1 ]] && ok "published fixture matches GNU file outputs"

[[ $(cat "$d/bos/pieces/1-aa") == $'alpha\nbeta' ]] && ok "1-aa is alpha/beta" || no "1-aa $(cat -A "$d/bos/pieces/1-aa" 2>/dev/null)"
[[ $(cat "$d/bos/pieces/1-ab") == gamma ]] && ok "1-ab is gamma" || no "1-ab $(cat -A "$d/bos/pieces/1-ab" 2>/dev/null)"
[[ $(cat "$d/bos/pieces/3-aa") == $'alpha\nbeta' && $(cat "$d/bos/pieces/3-ab") == gamma ]] \
  && ok "third invocation files are not empty" || no "third invocation missing content"

echo "split-check: $pass passed, $fail failed"
exit $(( fail>0 ? 1 : 0 ))
