#!/usr/bin/env bash
# tests/run.sh — the suite: both list variants build and prove themselves on the
# host, every source states its licence, and the two C harnesses exercise the
# httpd and rngseed loadables under AddressSanitizer+UBSan against the built tree.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; no(){ echo "FAIL $*"; fail=$((fail+1)); }
INC="-DHAVE_CONFIG_H -I$BT -I$BT/include -I$BT/builtins -I$BT/examples/loadables"

echo "== licences =="; bash tests/licence-check.sh >/dev/null && ok "licence-check" || no "licence-check"
echo "== default list =="
./build.sh >/dev/null 2>&1 && ok "builds out/bash" || { no "build"; echo "run: $pass passed, $fail failed"; exit 1; }
bash tests/host-smoke.sh out/bash config/bash-loadables.list >/dev/null 2>&1 && ok "host-smoke (default list)" || no "host-smoke (default list)"
python3 tests/regressions.py out/bash && ok "builtin regressions" || no "builtin regressions"
echo "== pure list =="
./build.sh --list config/bash-loadables-pure.list >/dev/null 2>&1 && ok "builds out/bash-pure" || no "build (pure)"
bash tests/host-smoke.sh out/bash-pure config/bash-loadables-pure.list >/dev/null 2>&1 && ok "host-smoke (pure list)" || no "host-smoke (pure list)"
[[ "$(out/bash-pure -c 'type -t ls' 2>/dev/null)" != builtin ]] && ok "pure build carries no ls (variants really differ)" || no "pure build has ls"
echo "== stat parity with coreutils =="
bash tests/stat-parity.sh out/bash | tail -1 | grep -qE 'SKIP|^stat-parity: ([0-9]+)/\1 ' && ok "stat-parity" || no "stat-parity"
echo "== static + a root filesystem of only bash =="
./build.sh --static >/dev/null 2>&1 && ok "builds out/bash-static" || no "build (static)"
bash tests/rootfs-smoke.sh out/bash-static | tail -1 | grep -qE 'SKIP|PASS' && ok "rootfs-smoke" || no "rootfs-smoke"
echo "== C harnesses (ASan+UBSan) =="
if [[ -f "$BT/config.h" ]] && command -v "$CC" >/dev/null; then
  for h in rngseed httpd; do
    d=$(mktemp -d); DFLAG=""; [[ $h == httpd ]] && DFLAG="-DHTTPD_REQUEST_TIMEOUT_MS=1000"
    if "$CC" -O1 -g -fsanitize=address,undefined $DFLAG $INC "loadables/$h.c" "tests/$h-host.c" -o "$d/t" >/dev/null 2>&1 && "$d/t" >/dev/null 2>&1
    then ok "$h contract"; else no "$h contract"; fi
    rm -rf "$d"
  done
else echo "SKIP C harnesses (need a built tree + $CC)"; fi
echo; echo "run: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
