#!/usr/bin/env bash
# tests/tutorial.sh — docs/anatomy-of-a-loadable.md, executed: the tutorial
# loadable builds as a shared object and loads with enable -f, and builds in
# through EXTRA_LOADABLES + a list of its own. Keeps the tutorial honest.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"; CC=${CC:-cc}
pass=0; fail=0; ok(){ echo "  PASS  $*"; pass=$((pass+1)); }; no(){ echo "  FAIL  $*"; fail=$((fail+1)); }
[[ -f "$BT/config.h" && -x out/bash ]] || { echo "tutorial: build first (./build.sh)"; exit 1; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT

echo "== as a shared object =="
if "$CC" -fPIC -shared -Wall -Wextra -Wno-unused-parameter -DHAVE_CONFIG_H -I$BT -I$BT/include -I$BT/builtins -I$BT/examples/loadables \
     docs/tutorial/greet.c -o "$d/greet.so" 2>"$d/cc.err"; then ok "greet.c compiles warning-free: $([[ -s $d/cc.err ]] && echo no || echo yes)"; else no "compile"; cat "$d/cc.err"; fi
out=$(out/bash -c "enable -f $d/greet.so greet && greet -n 2 -u bash && type -t greet" 2>&1)
[[ "$out" == $'hello, BASH\nhello, BASH\nbuiltin' ]] && ok "enable -f, options, type -t builtin" || no "enable -f: '$out'"
out=$(out/bash -c "enable -f $d/greet.so greet; greet -n 0 x; echo \$?" 2>/dev/null); [[ "$out" == 1 ]] && ok "error path returns 1" || no "error path: '$out'"
out/bash -c "enable -f $d/greet.so greet; greet --help" 2>/dev/null | grep -q 'Print a greeting' && ok "--help shows the long doc" || no "--help"

echo "== compiled in, through EXTRA_LOADABLES and a list of its own =="
printf 'greet|Print a greeting\n' > "$d/bash-loadables-tutorial.list"
if EXTRA_LOADABLES=docs/tutorial ./build.sh --list "$d/bash-loadables-tutorial.list" >/dev/null 2>&1; then
  ok "builds out/bash-tutorial"
  out=$(out/bash-tutorial -c 'PATH=; greet you; type -t greet; type -t ls || echo absent' 2>&1)
  [[ "$out" == $'hello, you\nbuiltin\nabsent' ]] && ok "greet is a builtin there, ls is not (the list is exact)" || no "static greet: '$out'"
else no "build with EXTRA_LOADABLES"; fi
echo; echo "tutorial: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
