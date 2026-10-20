#!/usr/bin/env bash
# Build each variant, check utility behavior, and run the sanitizer harnesses.
# Each producer's exit status is checked directly; a printed summary is not a verdict.
# Separate resource gates may run BASHOS_TEST_PHASE=build and then =bench.
# Both phases are required for a complete run; the default runs everything.
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
phase=${BASHOS_TEST_PHASE:-all}
case "$phase" in
  all|build) ;;
  bench)
    check 'loadable benchmark validation' python3 tests/bench-loadables.py
    if command -v busybox >/dev/null; then
      check 'bench outputs agree across userlands' bash bench/run.sh --quick
    else
      echo 'SKIP bench (no busybox)'
    fi
    printf '\nrun bench phase: %s passed, %s failed\n' "$pass" "$fail"
    [[ $fail == 0 ]]
    exit
    ;;
  *) echo "Unknown BASHOS_TEST_PHASE: $phase" >&2; exit 2 ;;
esac
check licence-check bash tests/licence-check.sh
check 'atomic executable publication' python3 tests/publish-binary.py
check 'complete build cache entries' python3 tests/build-cache.py
check 'configured build tree relocation' python3 tests/build-tree.py
check 'dependency cache integrity' python3 tests/dependency-cache.py
check 'optional interpreter cache integrity' python3 tests/interpreter-cache.py
check 'package producer input boundaries' python3 tests/package-inputs.py
check 'uv data publication' python3 tests/fetch-uv.py
if [[ $phase == all ]]; then
  check 'loadable benchmark validation' python3 tests/bench-loadables.py
else
  echo 'DEFER benchmark validation to required BASHOS_TEST_PHASE=bench run'
fi
check 'benchmark publication integrity' python3 tests/bench-publish.py
check profiles python3 tests/profiles.py
if ./build.sh >"$scratch/build.log" 2>&1; then
  echo 'PASS builds out/bash'; pass=$((pass+1))
else
  cat "$scratch/build.log"; echo 'FAIL default build'; exit 1
fi
check 'host-smoke (default list)' bash tests/host-smoke.sh out/bash config/bash-loadables.list
check 'builtin regressions' python3 tests/regressions.py out/bash
check 'crypto independent byte contracts' python3 tests/sol-crypto-check.py out/bash
check 'more paging contracts' python3 tests/sol-more-check.py out/bash
check 'more shared key consumers' python3 tests/sol-more-helper-check.py out/bash
check 'vi deletion and UTF-8 endpoints' env OPUS_VI_REQUIRE_NVIM=1 python3 tests/opus-vi-dd.py out/bash
for name in cmp-streams cp-safety mv-safety split-safety diff-safety dd-safety; do
  check "$name" python3 "tests/$name.py" out/bash
done
check 'copy/move finalization failures' python3 tests/copy-move-errors.py out/bash
check 'Debian command parity' python3 tests/debian-parity.py out/bash
check 'paste and uniq parity' python3 tests/paste-uniq-parity.py out/bash
check 'tac parity' python3 tests/tac-parity.py out/bash
for name in head-sed fold expand bc nl pr; do
  check "$name parity" python3 "tests/$name-parity.py" out/bash
done
check 'passwd fields' python3 tests/passwd-fields.py out/bash
check 'mktemp -u' bash tests/mktemp-u-check.sh out/bash
check 'dmesg split fixture' python3 tests/dmesg-fixture.py out/bash
for name in pattern-fastpaths join-reuse pcre-streams sed-streams rev-streams core-fastpaths coreutils-fastpaths pack-cache index-cache xargs-spawn pager-interrupts install-truncate; do
  check "$name" python3 "tests/$name.py" out/bash
done
check 'git object store' python3 tests/git-odb.py out/bash
check 'git untrusted objects and paths' python3 tests/git-integrity.py out/bash
check 'git apply path preflight' python3 tests/git-apply-paths.py out/bash
check 'git refs across implementations' python3 tests/git-refs.py out/bash
check 'git packs across implementations' python3 tests/git-packs.py out/bash
check 'git protocol across implementations' python3 tests/git-proto.py out/bash
check 'git over http' python3 tests/git-http.py out/bash
check 'git over ssh' python3 tests/git-ssh.py out/bash
check 'git signing against ssh-keygen' python3 tests/git-signing.py out/bash
check 'git parity against real git' python3 tests/git-parity.py out/bash
check 'builds out/bash-pure' ./build.sh --list config/bash-loadables-pure.list
check 'host-smoke (pure list)' bash tests/host-smoke.sh out/bash-pure config/bash-loadables-pure.list
if [[ "$(out/bash-pure -c 'type -t ls' 2>/dev/null)" != builtin ]]; then
  echo 'PASS pure build carries no ls'; pass=$((pass+1))
else
  echo 'FAIL pure build has ls'; fail=$((fail+1))
fi
for name in wc-tail-parity text-tools-parity util-linux-smoke system-smoke seq-parity sort-parity zstd-check hostid-check free-check timeout-check uptime-check truncate-check cp-check tail-check mv-check chmod-check du-check crypto-check ar-check diff-check split-check csplit-check col-check colrm-check column-check strings-check od-check hexdump-check tee-check join-check comm-check unexpand-check rev-check sort-check wc-check grep-parity cut-parity stat-parity repeat-input-check col-newline-check nproc-check; do
  check "$name" bash "tests/$name.sh" out/bash
done
check network-smoke python3 tests/network-smoke.py out/bash
check 'curl HTTPS and redirects' python3 tests/curl-https.py out/bash
check misc-smoke python3 tests/misc-smoke.py out/bash
check 'bashlogger private datagrams' python3 tests/sol-bashlogger-socket.py out/bash
check 'bashsyslogd private routing' python3 tests/sol-bashsyslogd-check.py out/bash
check terminal-smoke python3 tests/terminal-smoke.py out/bash
check 'FIFO queue contracts' python3 tests/sol-fifo-check.py out/bash
check 'terminal and buffer edges' python3 tests/vt-buf-edges.py out/bash
check 'expect whole-wait timeouts' python3 tests/expect-timeout.py out/bash
check gpu-smoke python3 tests/gpu-smoke.py out/bash
check ptybroker python3 tests/ptybroker.py --bash out/bash
check ptybroker-io python3 tests/ptybroker-io.py --bash out/bash
check screen-broker python3 tests/screen-broker.py --bash out/bash
check pty-primitives python3 tests/pty-primitives.py out/bash
check large-smoke python3 tests/large-smoke.py out/bash
check 'uclampset setters and validation' python3 tests/opus-uclampset.py out/bash
check 'bsdgames byte and stream contracts' python3 tests/sol-bsdgames-contracts.py out/bash
check helper-smoke python3 tests/helper-smoke.py out/bash
check procstat-smoke python3 tests/procstat-smoke.py out/bash
check final-smoke python3 tests/final-smoke.py out/bash
check 'builds out/bash-static' ./build.sh --static
check 'static builtin regressions' python3 tests/regressions.py out/bash-static
check 'static crypto independent byte contracts' python3 tests/sol-crypto-check.py out/bash-static
check 'static more paging contracts' python3 tests/sol-more-check.py out/bash-static
check 'static vi deletion and UTF-8 endpoints' env OPUS_VI_REQUIRE_NVIM=1 python3 tests/opus-vi-dd.py out/bash-static
for name in cmp-streams cp-safety mv-safety split-safety diff-safety dd-safety; do
  check "static $name" python3 "tests/$name.py" out/bash-static
done
check 'static Debian command parity' python3 tests/debian-parity.py out/bash-static
check 'static tac parity' python3 tests/tac-parity.py out/bash-static
for name in head-sed fold expand bc nl pr; do
  check "static $name parity" python3 "tests/$name-parity.py" out/bash-static
done
for name in pattern-fastpaths join-reuse pcre-streams sed-streams rev-streams core-fastpaths coreutils-fastpaths pack-cache index-cache xargs-spawn pager-interrupts install-truncate; do
  check "static $name" python3 "tests/$name.py" out/bash-static
done
check 'static final imports' python3 tests/final-smoke.py out/bash-static
check 'static bashlogger private datagrams' python3 tests/sol-bashlogger-socket.py out/bash-static
check 'static bashsyslogd private routing' python3 tests/sol-bashsyslogd-check.py out/bash-static
check 'static bsdgames byte and stream contracts' python3 tests/sol-bsdgames-contracts.py out/bash-static
# The git builtin in the static build, which links its zlib in rather than
# finding one: a handful of scenarios is enough to see that it reads and
# writes a repository the same way there.
check 'static git parity' python3 tests/git-parity.py out/bash-static \
  basic-commit branches log-diff packs
check 'static git untrusted objects and paths' python3 tests/git-integrity.py out/bash-static
check 'static git apply path preflight' python3 tests/git-apply-paths.py out/bash-static
check 'static graphics' python3 tests/gpu-smoke.py out/bash-static
check 'static FIFO queue contracts' python3 tests/sol-fifo-check.py out/bash-static
check 'static terminal and buffer edges' python3 tests/vt-buf-edges.py out/bash-static
check 'static expect whole-wait timeouts' python3 tests/expect-timeout.py out/bash-static
check rootfs-smoke bash tests/rootfs-smoke.sh out/bash-static
check runtime-loadables bash tests/runtime-loadables.sh out/bash
check 'pkg signatures and remote install' python3 tests/pkg-signify.py out/bash
check 'package publication and rollback safety' python3 tests/pkg-safety.py out/bash
check 'package trust files' python3 tests/pkg-trust.py out/bash
for name in process-wrapper-state process-numeric device-fixtures signal-lookup sysctl-readonly nc-stream http-framing userdb-records cron-spool crypto-state; do
  check "$name" python3 "tests/$name.py" out/bash
  check "static $name" python3 "tests/$name.py" out/bash-static
done
check 'static package publication and rollback safety' python3 tests/pkg-safety.py out/bash-static
check 'static package trust files' python3 tests/pkg-trust.py out/bash-static
check tutorial bash tests/tutorial.sh
if [[ $phase == build ]]; then
  echo 'DEFER userland benchmark to required BASHOS_TEST_PHASE=bench run'
elif command -v busybox >/dev/null; then
  check 'bench outputs agree across userlands' bash bench/run.sh --quick
else
  echo 'SKIP bench (no busybox)'
fi
INC=(-DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
if [[ -f "$BT/config.h" ]] && command -v "$CC" >/dev/null; then
  check 'crypto independent contracts under ASan+UBSan' env BASHOS_TASK_DIR="$scratch/crypto-contracts" bash tests/sol-crypto-sanitize.sh out/bash
  check 'more under ASan+UBSan' env BASHOS_TASK_DIR="$scratch/more" bash tests/sol-more-sanitize.sh out/bash
  check 'vi deletion under ASan+UBSan' env OPUS_VI_REQUIRE_NVIM=1 bash tests/opus-vi-sanitize.sh out/bash
  check 'bashlogger fixture build' bash tests/sol-bashlogger-build-fixtures.sh "$scratch/bashlogger"
  check 'bashlogger descriptor and send failures' python3 tests/sol-bashlogger-socket.py out/bash \
    --shim "$scratch/bashlogger/syscalls.so"
  check 'bashlogger under ASan+UBSan' python3 tests/sol-bashlogger-socket.py out/bash \
    --module "$scratch/bashlogger/bashlogger-sanitize.so" \
    --asan-runtime "$(cat "$scratch/bashlogger/libasan.path")"
  check 'blockdev fixture build' env BASHOS_TASK_DIR="$scratch/blockdev" bash tests/sol-blockdev-build.sh
  check 'blockdev ioctl contract' python3 tests/sol-blockdev-check.py --binary out/bash \
    --module "$scratch/blockdev/artifacts/blockdev.so"
  check 'blockdev under ASan+UBSan' python3 tests/sol-blockdev-check.py --binary out/bash \
    --module "$scratch/blockdev/artifacts/blockdev-sanitize.so" \
    --preload "$(cat "$scratch/blockdev/artifacts/asan-path.txt")"
  check 'bashsyslogd fixture build' bash tests/sol-bashsyslogd-build-fixtures.sh "$scratch/bashsyslogd"
  check 'bashsyslogd forwarding and queue failures' python3 tests/sol-bashsyslogd-check.py out/bash \
    --fixture "$scratch/bashsyslogd/faults.so" \
    --allocation-module "$scratch/bashsyslogd/bashsyslogd-alloc.so"
  check 'bashsyslogd under ASan+UBSan' python3 tests/sol-bashsyslogd-check.py out/bash \
    --fixture "$scratch/bashsyslogd/faults.so" \
    --module "$scratch/bashsyslogd/bashsyslogd-sanitize.so" \
    --allocation-module "$scratch/bashsyslogd/bashsyslogd-alloc-sanitize.so" \
    --asan "$(cat "$scratch/bashsyslogd/libasan.path")"
  check 'core file and stream safety under ASan+UBSan' bash tests/core-io-sanitize.sh out/bash
  check 'bsdgames fixture build' env BASHOS_TASK_DIR="$scratch/bsdgames" bash tests/sol-bsdgames-build.sh
  check 'bsdgames under ASan+UBSan' env \
    BSDGAMES_LOAD_ENV="$scratch/bsdgames/load-sanitize.sh" \
    BSDGAMES_ASAN_LIB="$(cat "$scratch/bsdgames/asan-library.txt")" \
    python3 tests/sol-bsdgames-contracts.py out/bash
  check 'Debian command parity under ASan+UBSan' bash tests/debian-sanitize.sh out/bash
  check 'package publication and rollback under ASan+UBSan' bash tests/pkg-sanitize.sh out/bash
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
  check 'terminal and buffer edges under ASan+UBSan' bash tests/vt-buf-sanitize.sh out/bash
  check 'graphics under ASan+UBSan' bash tests/gpu-sanitize.sh out/bash
  check 'git under ASan+UBSan' bash tests/git-sanitize.sh out/bash
  check 'uclampset under ASan+UBSan' bash tests/opus-uclampset-sanitize.sh out/bash
  check 'process and device modules under ASan+UBSan' bash tests/system-process-sanitize.sh out/bash
  for name in nc http userdb spool crypto-state; do
    check "$name under ASan+UBSan" bash "tests/$name-sanitize.sh" out/bash
  done
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
  echo "FAIL C harness prerequisites (need a built tree + $CC)"; fail=$((fail+1))
fi
# Last, because the packages compile against the tree this build leaves behind.
check 'builds out/bash-shell' ./build.sh --profile shell --clean
check 'package producer and signed release' python3 tests/packages.py out/bash
check 'loadable package data files' python3 tests/pkg-data.py out/bash
check 'uv builtin' python3 tests/uv-builtin.py out/bash
printf '\nrun: %s passed, %s failed\n' "$pass" "$fail"
[[ $fail == 0 ]]
