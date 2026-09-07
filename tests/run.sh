#!/usr/bin/env bash
# Build each variant, check utility behavior, and run the sanitizer harnesses.
# Each producer's exit status is checked directly; a printed summary is not a verdict.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
pass=0; fail=0
scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
check(){
  local label=$1; shift
  if "$@" >"$scratch/check.log" 2>&1; then
    printf 'PASS %s\n' "$label"; pass=$((pass+1))
    tail -1 "$scratch/check.log"
  else
    local rc=$?
    cat "$scratch/check.log"
    printf 'FAIL %s (exit %s)\n' "$label" "$rc"; fail=$((fail+1))
  fi
}
check licence-check bash tests/licence-check.sh
if ./build.sh >"$scratch/build.log" 2>&1; then
  echo 'PASS builds out/bash'; pass=$((pass+1))
else
  cat "$scratch/build.log"; echo 'FAIL default build'; exit 1
fi
check 'host-smoke (default list)' bash tests/host-smoke.sh out/bash config/bash-loadables.list
check 'builtin regressions' python3 tests/regressions.py out/bash
check 'builds out/bash-pure' ./build.sh --list config/bash-loadables-pure.list
check 'host-smoke (pure list)' bash tests/host-smoke.sh out/bash-pure config/bash-loadables-pure.list
if [[ "$(out/bash-pure -c 'type -t ls' 2>/dev/null)" != builtin ]]; then
  echo 'PASS pure build carries no ls'; pass=$((pass+1))
else
  echo 'FAIL pure build has ls'; fail=$((fail+1))
fi
for name in wc-tail-parity text-tools-parity util-linux-smoke system-smoke seq-parity sort-parity zstd-check grep-parity cut-parity stat-parity; do
  check "$name" bash "tests/$name.sh" out/bash
done
check network-smoke python3 tests/network-smoke.py out/bash
check misc-smoke python3 tests/misc-smoke.py out/bash
check 'builds out/bash-static' ./build.sh --static
check 'static builtin regressions' python3 tests/regressions.py out/bash-static
check rootfs-smoke bash tests/rootfs-smoke.sh out/bash-static
check runtime-loadables bash tests/runtime-loadables.sh out/bash
check tutorial bash tests/tutorial.sh
if command -v busybox >/dev/null; then
  check 'bench outputs agree across userlands' bash bench/run.sh --quick
else
  echo 'SKIP bench (no busybox)'
fi
INC=(-DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
if [[ -f "$BT/config.h" ]] && command -v "$CC" >/dev/null; then
  if "$CC" -O1 -g -fsanitize=address,undefined tests/privdrop-host.c -o "$scratch/privdrop"; then
    check 'account parser contract' "$scratch/privdrop"
  else
    echo 'FAIL account parser harness compilation'; fail=$((fail+1))
  fi
  for h in rngseed httpd zstd; do
    flags=(); [[ $h != httpd ]] || flags=(-DHTTPD_REQUEST_TIMEOUT_MS=1000)
    if "$CC" -O1 -g -fsanitize=address,undefined "${flags[@]}" "${INC[@]}" "loadables/$h.c" "tests/$h-host.c" -o "$scratch/$h"; then
      check "$h contract" "$scratch/$h"
    else
      echo "FAIL $h harness compilation"; fail=$((fail+1))
    fi
  done
  if "$CC" -O1 -g -fsanitize=address,undefined "${INC[@]}" loadables/grep.c tests/grep-host.c -o "$scratch/grep"; then
    check 'grep parity under ASan+UBSan' env GREP_IMPL="$scratch/grep" bash tests/grep-parity.sh out/bash
  else
    echo 'FAIL grep harness compilation'; fail=$((fail+1))
  fi
else
  echo "SKIP C harnesses (need a built tree + $CC)"
fi
printf '\nrun: %s passed, %s failed\n' "$pass" "$fail"
[[ $fail == 0 ]]
