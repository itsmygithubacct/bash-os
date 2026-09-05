#!/usr/bin/env bash
# tests/host-smoke.sh — build bash-os and prove the loadables are real builtins.
# The claim bash-os makes is "no busybox, no coreutils": every covered command is
# a shell builtin reached with an EMPTY PATH. This test is that claim, executable.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); BX="$HERE/out/bash"
pass=0; fail=0
ok(){ echo "  PASS  $*"; pass=$((pass+1)); }
no(){ echo "  FAIL  $*"; fail=$((fail+1)); }

[[ -x "$BX" ]] || { echo "building bash-os first..."; ( cd "$HERE" && ./build.sh ) || { echo "build failed"; exit 1; }; }

echo "== the shipped commands are builtins, not externals =="
for c in ls grep sed wc ps df httpd rngseed ip hostname; do
  t=$("$BX" -c "type -t $c" 2>/dev/null)
  [[ "$t" == builtin ]] && ok "$c is a builtin" || no "$c is '$t', not a builtin"
done

echo "== they run with an EMPTY PATH (no external binary reachable) =="
out=$("$BX" -c 'PATH=; printf "a\nb\nc\n" | grep b' 2>/dev/null); [[ "$out" == b ]] && ok "grep works, PATH empty" || no "grep: '$out'"
out=$("$BX" -c 'PATH=; printf "x y z\n" | wc -w' 2>/dev/null);   [[ "$out" == 3 ]] && ok "wc works, PATH empty"   || no "wc: '$out'"
out=$("$BX" -c 'PATH=; seq 3 | tr "\n" ","' 2>/dev/null);        [[ "$out" == "1,2,3," ]] && ok "seq|tr works, PATH empty" || no "seq|tr: '$out'"
"$BX" -c 'PATH=; help httpd' >/dev/null 2>&1 && ok "httpd builtin has help text" || no "httpd help missing"

echo "== still a normal shell =="
out=$("$BX" -c 'x=5; for i in 1 2 3; do ((x+=i)); done; echo $x' 2>/dev/null)
[[ "$out" == 11 ]] && ok "arithmetic, loops, variables" || no "shell semantics: '$out'"

n=$("$BX" -c 'enable -a | wc -l' 2>/dev/null)
[[ "$n" -gt 120 ]] && ok "$n builtins enabled (stock bash has ~61)" || no "only $n builtins"

echo; echo "host-smoke: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
