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
check 'atomic executable publication' python3 tests/publish-binary.py
check 'loadable benchmark validation' python3 tests/bench-loadables.py
check profiles python3 tests/profiles.py
if ./build.sh >"$scratch/build.log" 2>&1; then
  echo 'PASS builds out/bash'; pass=$((pass+1))
else
  cat "$scratch/build.log"; echo 'FAIL default build'; exit 1
fi
check 'host-smoke (default list)' bash tests/host-smoke.sh out/bash config/bash-loadables.list
check 'builtin regressions' python3 tests/regressions.py out/bash
check 'paste and uniq parity' python3 tests/paste-uniq-parity.py out/bash
check 'tac parity' python3 tests/tac-parity.py out/bash
for name in head-sed fold expand bc nl pr; do
  check "$name parity" python3 "tests/$name-parity.py" out/bash
done
for name in pattern-fastpaths join-reuse pcre-streams sed-streams rev-streams core-fastpaths coreutils-fastpaths pack-cache index-cache xargs-spawn pager-interrupts install-truncate; do
  check "$name" python3 "tests/$name.py" out/bash
done
check 'git object store' python3 tests/git-odb.py out/bash
check 'git refs across implementations' python3 tests/git-refs.py out/bash
check 'git parity against real git' python3 tests/git-parity.py out/bash
check 'builds out/bash-pure' ./build.sh --list config/bash-loadables-pure.list
check 'host-smoke (pure list)' bash tests/host-smoke.sh out/bash-pure config/bash-loadables-pure.list
if [[ "$(out/bash-pure -c 'type -t ls' 2>/dev/null)" != builtin ]]; then
  echo 'PASS pure build carries no ls'; pass=$((pass+1))
else
  echo 'FAIL pure build has ls'; fail=$((fail+1))
fi
for name in wc-tail-parity text-tools-parity util-linux-smoke system-smoke seq-parity sort-parity zstd-check hostid-check free-check timeout-check uptime-check truncate-check cp-check tail-check mv-check du-check crypto-check ar-check diff-check split-check csplit-check col-check colrm-check column-check strings-check od-check hexdump-check tee-check join-check comm-check unexpand-check rev-check sort-check wc-check grep-parity cut-parity stat-parity repeat-input-check col-newline-check nproc-check; do
  check "$name" bash "tests/$name.sh" out/bash
done
check network-smoke python3 tests/network-smoke.py out/bash
check 'curl HTTPS and redirects' python3 tests/curl-https.py out/bash
check misc-smoke python3 tests/misc-smoke.py out/bash
check terminal-smoke python3 tests/terminal-smoke.py out/bash
check gpu-smoke python3 tests/gpu-smoke.py out/bash
check ptybroker python3 tests/ptybroker.py --bash out/bash
check ptybroker-io python3 tests/ptybroker-io.py --bash out/bash
check screen-broker python3 tests/screen-broker.py --bash out/bash
check pty-primitives python3 tests/pty-primitives.py out/bash
check large-smoke python3 tests/large-smoke.py out/bash
check helper-smoke python3 tests/helper-smoke.py out/bash
check procstat-smoke python3 tests/procstat-smoke.py out/bash
check final-smoke python3 tests/final-smoke.py out/bash
check 'builds out/bash-static' ./build.sh --static
check 'static builtin regressions' python3 tests/regressions.py out/bash-static
check 'static tac parity' python3 tests/tac-parity.py out/bash-static
for name in head-sed fold expand bc nl pr; do
  check "static $name parity" python3 "tests/$name-parity.py" out/bash-static
done
for name in pattern-fastpaths join-reuse pcre-streams sed-streams rev-streams core-fastpaths coreutils-fastpaths pack-cache index-cache xargs-spawn pager-interrupts install-truncate; do
  check "static $name" python3 "tests/$name.py" out/bash-static
done
check 'static final imports' python3 tests/final-smoke.py out/bash-static
check 'static graphics' python3 tests/gpu-smoke.py out/bash-static
check rootfs-smoke bash tests/rootfs-smoke.sh out/bash-static
check runtime-loadables bash tests/runtime-loadables.sh out/bash
check 'pkg signatures and remote install' python3 tests/pkg-signify.py out/bash
check tutorial bash tests/tutorial.sh
if command -v busybox >/dev/null; then
  check 'bench outputs agree across userlands' bash bench/run.sh --quick
else
  echo 'SKIP bench (no busybox)'
fi
INC=(-DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
if [[ -f "$BT/config.h" ]] && command -v "$CC" >/dev/null; then
  check 'paste and uniq under ASan+UBSan' bash tests/paste-uniq-sanitize.sh out/bash
  check 'tac under ASan+UBSan' bash tests/tac-sanitize.sh out/bash
  for name in head-sed fold expand bc nl pr; do
    check "$name under ASan+UBSan" bash "tests/$name-sanitize.sh" out/bash
  done
  check 'procstat under ASan+UBSan' bash tests/procstat-sanitize.sh out/bash
  check 'helper modules under ASan+UBSan' bash tests/helper-sanitize.sh out/bash
  check 'final modules under ASan+UBSan' bash tests/final-sanitize.sh out/bash
  check 'large modules under ASan+UBSan' bash tests/large-sanitize.sh out/bash
  check 'terminal modules under ASan+UBSan' bash tests/terminal-sanitize.sh out/bash
  check 'graphics under ASan+UBSan' bash tests/gpu-sanitize.sh out/bash
  check 'git under ASan+UBSan' bash tests/git-sanitize.sh out/bash
  if "$CC" -O1 -g -fsanitize=address,undefined tests/privdrop-host.c -o "$scratch/privdrop"; then
    check 'account parser contract' "$scratch/privdrop"
  else
    echo 'FAIL account parser harness compilation'; fail=$((fail+1))
  fi
  for h in rngseed httpd zstd; do
    flags=(); [[ $h != httpd ]] || flags=(-DHTTPD_REQUEST_TIMEOUT_MS=1000)
    libs=(); [[ $h != zstd ]] || libs=(-lzstd)
    if "$CC" -O1 -g -fsanitize=address,undefined "${flags[@]}" "${INC[@]}" "loadables/$h.c" "tests/$h-host.c" "${libs[@]}" -o "$scratch/$h"; then
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
# Last, because the packages compile against the tree this build leaves behind.
check 'builds out/bash-shell' ./build.sh --profile shell --clean
check 'package producer and signed release' python3 tests/packages.py out/bash
check 'loadable package data files' python3 tests/pkg-data.py out/bash
check 'uv builtin' python3 tests/uv-builtin.py out/bash
printf '\nrun: %s passed, %s failed\n' "$pass" "$fail"
[[ $fail == 0 ]]
