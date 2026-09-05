#!/usr/bin/env bash
# tests/run.sh — build bash-os, then the host checks. The C harnesses link the
# real loadable sources against the built bash tree (build/bash-5.3), stubbing
# the few bash runtime symbols, and exercise them under AddressSanitizer+UBSan.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; no(){ echo "FAIL $*"; fail=$((fail+1)); }
INC="-DHAVE_CONFIG_H -I$BT -I$BT/include -I$BT/builtins -I$BT/examples/loadables"

echo "== build =="; ./build.sh >/dev/null 2>&1 && ok "bash-os builds" || { no "build"; echo "run: $pass/$((pass+fail))"; exit 1; }
echo "== host smoke (builtins with empty PATH) =="; bash tests/host-smoke.sh >/dev/null 2>&1 && ok "host-smoke" || no "host-smoke"

if [[ -f "$BT/config.h" ]] && command -v cc >/dev/null; then
  for h in rngseed httpd; do
    d=$(mktemp -d); DFLAG=""; [ "$h" = httpd ] && DFLAG="-DHTTPD_REQUEST_TIMEOUT_MS=1000"
    if cc -O1 -g -fsanitize=address,undefined $DFLAG $INC \
         "loadables/$h.c" "tests/$h-host.c" -o "$d/t" >/dev/null 2>&1 && "$d/t" >/dev/null 2>&1
    then ok "$h contract (ASan+UBSan)"; else no "$h contract"; fi
    rm -rf "$d"
  done
else echo "SKIP C harnesses (need a built tree + cc)"; fi

echo; echo "run: $pass passed, $fail failed"; exit $(( fail>0 ? 1 : 0 ))
