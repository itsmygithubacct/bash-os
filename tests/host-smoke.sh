#!/usr/bin/env bash
# tests/host-smoke.sh [BINARY] [LIST] — prove a built bash-os is what it claims.
# The claim is "no busybox, no coreutils": every command in the list is a shell
# builtin, reached with an EMPTY PATH. This test is that claim, executable.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=${1:-$HERE/out/bash}; LIST=${2:-$HERE/config/bash-loadables.list}
source "$HERE/config/loadables.sh"
mapfile -t NAMES < <(loadables_names "$LIST")
has(){ local n; for n in "${NAMES[@]}"; do [[ $n == "$1" ]] && return 0; done; return 1; }
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
[[ -x "$BX" ]] || { echo "no binary at $BX (run ./build.sh)"; exit 1; }

echo "== every listed name is a builtin, with help text (${#NAMES[@]} names, $(basename "$LIST")) =="
nb=0; nh=0
for n in "${NAMES[@]}"; do
  [[ "$("$BX" -c "type -t $n" 2>/dev/null)" == builtin ]] || { echo "  not a builtin: $n"; nb=$((nb+1)); }
  "$BX" -c "help $n" >/dev/null 2>&1 || { echo "  no help text: $n"; nh=$((nh+1)); }
done
[[ $nb == 0 ]] && ok "all ${#NAMES[@]} names are builtins" || no "$nb names are not builtins"
[[ $nh == 0 ]] && ok "all ${#NAMES[@]} names have help text" || no "$nh names lack help text"

echo "== they run with an EMPTY PATH (no external binary reachable) =="
if has cat;      then out=$("$BX" -c 'PATH=; printf "hi\n" | cat' 2>/dev/null);         [[ "$out" == hi ]]     && ok "cat"      || no "cat: '$out'"; fi
if has basename; then out=$("$BX" -c 'PATH=; basename /a/b.c' 2>/dev/null);              [[ "$out" == b.c ]]    && ok "basename" || no "basename: '$out'"; fi
if has seq;      then out=$("$BX" -c 'PATH=; seq 3' 2>/dev/null | tr '\n' ,);            [[ "$out" == "1,2,3," ]] && ok "seq"    || no "seq: '$out'"; fi
if has grep;     then out=$("$BX" -c 'PATH=; printf "a\nb\nc\n" | grep b' 2>/dev/null);  [[ "$out" == b ]]      && ok "grep"     || no "grep: '$out'"; fi
if has wc;       then out=$("$BX" -c 'PATH=; printf "x y z\n" | wc -w' 2>/dev/null);     [[ "$out" == 3 ]]      && ok "wc"       || no "wc: '$out'"; fi
if has pax;      then out=$("$BX" -c 'PATH=; d=$(mktemp -d); cd "$d"; printf "data\n" > f; pax -w f > a.tar; mkdir x; cd x; pax -r < ../a.tar; cat f; cd /; rm -r "$d"' 2>/dev/null)
                      [[ "$out" == data ]]  && ok "pax write/read round-trip" || no "pax: '$out'"; fi

if has stat; then
  d=$(mktemp -d); printf 12345 > "$d/f"; mkdir "$d/dir"; ln -s f "$d/l"
  out=$("$BX" -c "PATH=; stat -c%s $d/f" 2>/dev/null);                    [[ "$out" == 5 ]] && ok "stat -c%s (the form scripts use)" || no "stat -c%s: '$out'"
  out=$("$BX" -c "PATH=; stat -c '%F|%A' $d/dir" 2>/dev/null);             [[ "$out" == "directory|d"* ]] && ok "stat -c '%F|%A'" || no "stat -c %F|%A: '$out'"
  out=$("$BX" -c "PATH=; stat --printf=%s $d/f; echo END" 2>/dev/null);   [[ "$out" == 5END ]] && ok "stat --printf (no newline)" || no "stat --printf: '$out'"
  out=$("$BX" -c "PATH=; stat -t $d/f" 2>/dev/null | wc -w);              [[ "$out" == 16 ]] && ok "stat -t has 16 fields" || no "stat -t: $out fields"
  out=$("$BX" -c "PATH=; stat -c%F $d/l; stat -L -c%F $d/l" 2>/dev/null | tr '\n' ,)
  [[ "$out" == "symbolic link,regular file," ]] && ok "stat on a symlink, -L follows it" || no "stat symlink: '$out'"
  out=$("$BX" -c "PATH=; stat -A S $d/f && echo \${S[size]}:\${S[type]}" 2>/dev/null); [[ "$out" == "5:regular file" ]] && ok "stat -A NAME" || no "stat -A: '$out'"
  out=$("$BX" -c "PATH=; stat $d/f | head -1" 2>/dev/null);               [[ "$out" == "  File: $d/f" ]] && ok "stat default layout" || no "stat default: '$out'"
  "$BX" -c "PATH=; stat $d/nope" >/dev/null 2>&1 && no "stat of a missing file exits 0" || ok "stat of a missing file fails"
  rm -rf "$d"
fi

echo "== still a normal shell =="
out=$("$BX" -c 'x=5; for i in 1 2 3; do ((x+=i)); done; echo $x' 2>/dev/null)
[[ "$out" == 11 ]] && ok "arithmetic, loops, variables" || no "shell semantics: '$out'"
n=$("$BX" -c 'enable -a | wc -l' 2>/dev/null)
[[ "$n" -ge $(( ${#NAMES[@]} + 50 )) ]] && ok "$n builtins enabled (bash's own plus the ${#NAMES[@]} injected)" || no "only $n builtins enabled"

echo; echo "host-smoke: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
