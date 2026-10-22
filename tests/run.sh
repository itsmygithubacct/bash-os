#!/usr/bin/env bash
# Build each variant, check utility behavior, and run the sanitizer harnesses.
# Each producer's exit status is checked directly; a printed summary is not a verdict.
# Separate resource gates may run BASHOS_TEST_PHASE=build and then =bench.
# Both phases are required for a complete run; the default runs everything.
set -euo pipefail
unset PYTHONOPTIMIZE  # Keep independent Python validation assertions enabled.
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
check 'clip contract' python3 tests/sol-clip-check.py out/bash
check 'lpr list readdir error' python3 tests/sol-lpr-list-readdir.py out/bash
check 'tui persistent screen and terminal contracts' python3 tests/sol-tui-check.py out/bash
check 'lpr private spool and configured backend' python3 tests/opus-lpr-delivery.py out/bash
check 'git lifecycle wait and repository state' python3 tests/sol-git-lifecycle.py out/bash
check 'git workload oracle corruption controls' python3 tests/sol-git-oracles.py
check 'gpu independent oracle controls' python3 tests/sol-gpu-oracle-check.py
check 'gpu CPU frame contracts (native device separate)' python3 tests/sol-gpu-frames.py out/bash
check 'buf transactional contracts' python3 tests/sol-buf-check.py out/bash
check 'screen live relay streams' env TMPDIR=/tmp python3 tests/sol-screen-streams.py --bash out/bash --output "$scratch/screen-streams.json"
check 'vi unterminated tail deletion' python3 tests/sol-vi-delete.py out/bash
check 'bc call-state and input-base contracts' python3 tests/sol-bc-regression.py out/bash
check 'pr sol-pr-cli contracts' python3 tests/sol-pr-cli.py out/bash
check 'pr sol-pr-formfeed contracts' python3 tests/sol-pr-formfeed.py out/bash
check 'pr sol-pr-pages contracts' python3 tests/sol-pr-pages.py out/bash
check 'pr sol-pr-stream contracts' python3 tests/sol-pr-stream.py out/bash
check 'pgrep complete regex and selector contracts' python3 tests/sol-pgrep-check.py out/bash
check 'process matcher version output recovery' python3 tests/review-pgrep-output.py out/bash
check 'ts resolved highlight and nano statusbar' env TS_REQUIRE_NANO_STATUSBAR=1 python3 tests/opus-ts-highlight.py out/bash
check 'required nano oracle and termios tools' python3 -c 'import shutil; assert all(shutil.which(n,path="/usr/bin:/bin") for n in ("nano","stty")), "Required GNU nano or stty missing"'
check 'nano private PTY and resolved highlight integration' env NANO_REQUIRE_RESOLVED_TS=1 python3 tests/opus-nano-pty.py out/bash
check 'nano session PTY contracts' env NANO_REQUIRE_RESOLVED_TS=1 python3 tests/sol-nano-pty.py out/bash
check 'nano rescue filename diagnostic' python3 tests/astra-nano-rescue.py out/bash
check 'coreutils dispatcher contracts' python3 tests/sol-coreutils-check.py out/bash
check 'grep PCRE2 and persistent state' python3 tests/sol-grep-check.py out/bash
check 'ptybroker bounded streams and ownership' env TMPDIR=/tmp python3 tests/sol-ptybroker-streams.py --bash out/bash --output "$scratch/ptybroker-streams.json"
check 'rsync isolated push parity' python3 tests/opus-rsync-check.py out/bash
check 'rsync merged source deletion' python3 tests/astra-rsync-delete.py out/bash
check 'sv owned readiness and backpressure' python3 tests/astra-sv-readiness.py out/bash
check 'RTSP private loopback protocol' python3 tests/sol-rtspcat-loopback.py --binary out/bash --report "$scratch/rtspcat-native.json"
check 'RTSP root-relative control URI' python3 tests/astra-rtspcat-control.py out/bash
check 'mail private queue and SMTP' python3 tests/sol-mail-check.py out/bash
check 'mail closed peer survival' python3 tests/astra-mail-disconnect.py out/bash
check 'mkfs private ext2 images' env PATH="$PATH:/usr/sbin:/sbin" python3 tests/sol-mkfs.py --binary out/bash --report "$scratch/mkfs-native.json"
check 'rngseed owned private files' bash tests/sol-rngseed-check.sh out/bash
check 'setpgid owned-child contracts' python3 tests/sol-setpgid-check.py --binary out/bash
check 'zstd bounded streaming and atomic output' python3 tests/sol-zstd-check.py out/bash
check 'payload isolated installer protocol' python3 tests/opus-payload-installer.py out/bash
check 'cluster owned membership and recovery' python3 tests/sol-cluster-membership.py out/bash
check 'join redirected stdin recovery' python3 tests/review-join-streams.py out/bash
check 'nl binary BRE contracts' python3 tests/sol-nl-check.py out/bash
check 'nl empty backreference branches' python3 tests/review-nl-backrefs.py out/bash
check 'head options and input ownership' python3 tests/sol-head-options.py out/bash
check 'head closed output integrity' python3 tests/review-head-descriptors.py out/bash
check 'sed regex hang' python3 tests/grok-sed-fix-regex-hang.py out/bash
check 'sed locale direct matches' python3 tests/grok-sed-fix-locale.py out/bash
check 'sed bracket delimiters' python3 tests/grok-sed-fix-bracket.py out/bash
check 'sed e continuation' python3 tests/grok-sed-fix-e.py out/bash
check 'sed version token' python3 tests/grok-sed-fix-version.py out/bash
check 'sed GNU byte and cycle parity' python3 tests/sol-sed-parity.py out/bash
check 'sed complete contracts' python3 tests/sol-sed-complete.py out/bash
check 'sed binary regex' python3 tests/sol-sed-binary-regex.py out/bash
check 'sed signal responsiveness' python3 tests/sol-sed-signals.py out/bash
check 'sed follow-up GNU contracts' python3 tests/opus-sed-followup-gnu.py out/bash
check 'sed in-place directory anchor' python3 tests/grok-sed-fix-inplace.py out/bash
check 'bc language and declaration scope' python3 tests/opus-bc-language.py out/bash
check 'fold complete options' python3 tests/sol-fold-check.py out/bash
check 'fold descriptor ownership' python3 tests/review-fold-descriptors.py out/bash
check 'expand complete options' python3 tests/sol-expand-options.py out/bash
check 'expand descriptor ownership' python3 tests/review-expand-descriptors.py out/bash
check 'PCRE capture and error contracts' python3 tests/sol-pcre-check.py out/bash
check 'wc locale and boundary contracts' python3 tests/sol-wc-check.py out/bash
check 'unexpand tab and stream contracts' python3 tests/sol-unexpand-parity.py out/bash
check 'crypto independent byte contracts' python3 tests/sol-crypto-check.py out/bash
check 'P-256 and ACME independent interoperability' python3 tests/p256-check.py out/bash --report out/p256-native.json
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
check 'tac anchor-plus parity' python3 tests/grok-tac-c1-parity.py out/bash --timeout 5
check 'tac regex hang' python3 tests/grok-tac-fix-hang.py out/bash --timeout 5
check 'tac follow-up regex' python3 tests/opus-tac-followup-regex.py out/bash --cases 4000
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
check 'index fault shim' "$CC" -O2 -Wall -Wextra -Werror -fPIC -shared tests/sol-index-faults.c -ldl -o "$scratch/index-faults.so"
check 'index formats' python3 tests/sol-index-formats.py --binary out/bash
check 'index contracts' python3 tests/sol-index-check.py --binary out/bash --shim "$scratch/index-faults.so" --output "$scratch/index-check.json"
check 'index regression stages' python3 tests/sol-index-regressions.py --binary out/bash --case stages
check 'index regression null-id' python3 tests/sol-index-regressions.py --binary out/bash --case null-id
check 'index regression v3' python3 tests/sol-index-regressions.py --binary out/bash --case v3
check 'index regression bounds' python3 tests/sol-index-regressions.py --binary out/bash --case bounds
check 'index parity v1-over-refusal' python3 tests/sol-index-parity.py --binary out/bash --case v1-over-refusal
check 'index parity v2-mismatch' python3 tests/sol-index-parity.py --binary out/bash --case v2-mismatch
check 'index parity v3-split-literal' python3 tests/sol-index-parity.py --binary out/bash --case v3-split-literal
check 'index parity v3-untr' python3 tests/sol-index-parity.py --binary out/bash --case v3-untr
check 'index benchmark scheduler' python3 tests/sol-index-bench-check.py
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
check 'expr hang guard' python3 tests/grok-expr-hang.py out/bash
check 'expr end-list realloc' python3 tests/grok-expr-ends.py out/bash
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
check 'uclampset setters and validation' python3 tests/sol-uclampset.py out/bash
check 'bsdgames byte and stream contracts' python3 tests/sol-bsdgames-contracts.py out/bash
check helper-smoke python3 tests/helper-smoke.py out/bash
check procstat-smoke python3 tests/procstat-smoke.py out/bash
check final-smoke python3 tests/final-smoke.py out/bash
check 'builds out/bash-static' ./build.sh --static
check 'static builtin regressions' python3 tests/regressions.py out/bash-static
check 'static tui persistent screen and terminal contracts' python3 tests/sol-tui-check.py out/bash-static
check 'static vi unterminated tail deletion' python3 tests/sol-vi-delete.py out/bash-static
check 'static bc call-state and input-base contracts' python3 tests/sol-bc-regression.py out/bash-static
check 'static pr sol-pr-cli contracts' python3 tests/sol-pr-cli.py out/bash-static
check 'static pr sol-pr-formfeed contracts' python3 tests/sol-pr-formfeed.py out/bash-static
check 'static pr sol-pr-pages contracts' python3 tests/sol-pr-pages.py out/bash-static
check 'static pr sol-pr-stream contracts' python3 tests/sol-pr-stream.py out/bash-static
check 'static PCRE capture and error contracts' python3 tests/sol-pcre-check.py out/bash-static
check 'static wc locale and boundary contracts' python3 tests/sol-wc-check.py out/bash-static
check 'static unexpand tab and stream contracts' python3 tests/sol-unexpand-parity.py out/bash-static
check 'static crypto independent byte contracts' python3 tests/sol-crypto-check.py out/bash-static
check 'static P-256 and ACME independent interoperability' python3 tests/p256-check.py out/bash-static --report out/p256-static.json
check 'static more paging contracts' python3 tests/sol-more-check.py out/bash-static
check 'static vi deletion and UTF-8 endpoints' env OPUS_VI_REQUIRE_NVIM=1 python3 tests/opus-vi-dd.py out/bash-static
for name in cmp-streams cp-safety mv-safety split-safety diff-safety dd-safety; do
  check "static $name" python3 "tests/$name.py" out/bash-static
done
check 'static Debian command parity' python3 tests/debian-parity.py out/bash-static
check 'static tac parity' python3 tests/tac-parity.py out/bash-static
check 'static tac anchor-plus parity' python3 tests/grok-tac-c1-parity.py out/bash-static --timeout 5
check 'static tac regex hang' python3 tests/grok-tac-fix-hang.py out/bash-static --timeout 5
check 'static tac follow-up regex' python3 tests/opus-tac-followup-regex.py out/bash-static --cases 4000
check 'static expr hang guard' python3 tests/grok-expr-hang.py out/bash-static
for name in head-sed fold expand bc nl pr; do
  check "static $name parity" python3 "tests/$name-parity.py" out/bash-static
done
check 'static sed regex hang' python3 tests/grok-sed-fix-regex-hang.py out/bash-static
check 'static sed locale direct matches' python3 tests/grok-sed-fix-locale.py out/bash-static
check 'static sed bracket delimiters' python3 tests/grok-sed-fix-bracket.py out/bash-static
check 'static sed e continuation' python3 tests/grok-sed-fix-e.py out/bash-static
check 'static sed version token' python3 tests/grok-sed-fix-version.py out/bash-static
check 'static sed GNU byte and cycle parity' python3 tests/sol-sed-parity.py out/bash-static
check 'static sed complete contracts' python3 tests/sol-sed-complete.py out/bash-static
check 'static sed binary regex' python3 tests/sol-sed-binary-regex.py out/bash-static
check 'static sed signal responsiveness' python3 tests/sol-sed-signals.py out/bash-static
check 'static sed follow-up GNU contracts' python3 tests/opus-sed-followup-gnu.py out/bash-static
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
# The fault shim is LD_PRELOAD and does not attach to this static bash.
check 'static index formats' python3 tests/sol-index-formats.py --binary out/bash-static
check 'static index regression stages' python3 tests/sol-index-regressions.py --binary out/bash-static --case stages
check 'static index regression null-id' python3 tests/sol-index-regressions.py --binary out/bash-static --case null-id
check 'static index regression v3' python3 tests/sol-index-regressions.py --binary out/bash-static --case v3
check 'static index regression bounds' python3 tests/sol-index-regressions.py --binary out/bash-static --case bounds
check 'static index parity v1-over-refusal' python3 tests/sol-index-parity.py --binary out/bash-static --case v1-over-refusal
check 'static index parity v2-mismatch' python3 tests/sol-index-parity.py --binary out/bash-static --case v2-mismatch
check 'static index parity v3-split-literal' python3 tests/sol-index-parity.py --binary out/bash-static --case v3-split-literal
check 'static index parity v3-untr' python3 tests/sol-index-parity.py --binary out/bash-static --case v3-untr
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
  check 'build P-256 arithmetic fixture' "$CC" -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 tests/p256-m-check.c -o "$scratch/p256-m-check"
  check 'P-256 arithmetic and ECDH' "$scratch/p256-m-check"
  check 'nano wait unit generate' python3 tests/astra-nano-wait.py loadables/nano.c "$scratch/nano-wait.c"
  check 'nano wait unit native compile' "$CC" -std=c11 -Wall -Wextra "$scratch/nano-wait.c" -o "$scratch/nano-wait"
  check 'nano wait unit native run' "$scratch/nano-wait"
  check 'nano wait unit sanitizer compile' "$CC" -std=c11 -g -fno-omit-frame-pointer -fsanitize=address,undefined "$scratch/nano-wait.c" -o "$scratch/nano-wait-asan"
  check 'nano wait unit sanitizer run' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/nano-wait-asan"
  check 'ts diff bounds unit generate' python3 tests/astra-ts-diff-bounds.py loadables/ts.c "$scratch/ts-bounds.c"
  check 'ts diff bounds unit native compile' "$CC" -std=c11 -Wall -Wextra "$scratch/ts-bounds.c" -o "$scratch/ts-bounds"
  check 'ts diff bounds unit native run' "$scratch/ts-bounds"
  check 'ts diff bounds unit sanitizer compile' "$CC" -std=c11 -g -fno-omit-frame-pointer -fsanitize=address,undefined "$scratch/ts-bounds.c" -o "$scratch/ts-bounds-asan"
  check 'ts diff bounds unit sanitizer run' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/ts-bounds-asan"
check 'clip probe build' bash tests/sol-clip-build-probe.sh "$scratch/clip-probe"
check 'clip rollback contracts' env CLIP_LOAD_ENV="$scratch/clip-probe/probe.sh" python3 tests/sol-clip-faults.py out/bash
check 'clip sanitizer contracts' env CLIP_LOAD_ENV="$scratch/clip-probe/plain.sh" CLIP_ASAN_LIB="$(cat "$scratch/clip-probe/asan-runtime.txt")" python3 tests/sol-clip-check.py out/bash
check 'clip sanitizer rollback contracts' env CLIP_LOAD_ENV="$scratch/clip-probe/sanitize.sh" CLIP_ASAN_LIB="$(cat "$scratch/clip-probe/asan-runtime.txt")" python3 tests/sol-clip-faults.py out/bash
check 'clip LONG_MAX index under sanitized probe' env CLIP_LOAD_ENV="$scratch/clip-probe/sanitize.sh" CLIP_ASAN_LIB="$(cat "$scratch/clip-probe/asan-runtime.txt")" python3 tests/sol-clip-check.py out/bash
  check 'su injected fixture build' python3 tests/sol-su-build.py "$scratch/su-native"
  check 'su authentication boundaries' python3 tests/sol-su-check.py --fixture "$scratch/su-native/fixture" --shell out/bash --oracle
  check 'su sanitized fixture build' python3 tests/sol-su-build.py "$scratch/su-sanitize" --sanitize
  check 'su boundaries under ASan+UBSan' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 python3 tests/sol-su-check.py --fixture "$scratch/su-sanitize/fixture" --oracle
  check 'tui and shared helpers sanitizer contracts' env BASHOS_TASK_DIR="$scratch/tui-contracts" bash tests/sol-tui-sanitize.sh out/bash
  check 'lpr delivery and cancel SIGPIPE under ASan+UBSan' bash tests/opus-lpr-sanitize.sh out/bash
  mkdir -p "$scratch/gpu-frames"
  touch "$scratch/gpu-frames/render.fixture"
  check 'gpu ABI fixture build' bash tests/sol-gpu-build-fixture.sh "$scratch/gpu-frames/driver.so"
  check 'gpu sanitized ABI fixture build' bash tests/sol-gpu-build-fixture.sh "$scratch/gpu-frames/driver-asan.so" --sanitize
  check 'gpu sanitized frame module build' bash tests/gpu-module.sh "$scratch/gpu-frames/gpu-asan.so" --sanitize
  check 'gpu ABI fixture error contracts' python3 tests/sol-gpu-errors.py out/bash "$scratch/gpu-frames/driver.so"
  check 'gpu ABI fixture frame contracts' python3 tests/sol-gpu-frames.py out/bash --device "$scratch/gpu-frames/render.fixture" --driver-fixture "$scratch/gpu-frames/driver.so"
  check 'gpu sanitizer ABI error contracts' env GPU_MODULE="$scratch/gpu-frames/gpu-asan.so" GPU_ASAN_LIB="$("$CC" -print-file-name=libasan.so)" python3 tests/sol-gpu-errors.py out/bash "$scratch/gpu-frames/driver-asan.so"
  check 'gpu sanitizer ABI frame contracts' env GPU_MODULE="$scratch/gpu-frames/gpu-asan.so" GPU_ASAN_LIB="$("$CC" -print-file-name=libasan.so)" python3 tests/sol-gpu-frames.py out/bash --device "$scratch/gpu-frames/render.fixture" --driver-fixture "$scratch/gpu-frames/driver-asan.so"
  mkdir -p "$scratch/pkill-contracts"
  check 'pkill interceptor build' "$CC" -std=gnu11 -Wall -Wextra -Werror -O2 -U_FORTIFY_SOURCE -fPIC -shared tests/sol-pkill-intercept.c -ldl -o "$scratch/pkill-contracts/pkill-intercept.so"
  check 'pkill sanitizer build' "$CC" -std=gnu11 -Wall -Wextra -Werror -g -O1 -U_FORTIFY_SOURCE -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -I tests/sol-pgrep-stubs tests/sol-pkill-harness.c -o "$scratch/pkill-contracts/pkill-sanitize"
  check 'pkill owned-child and intercepted contracts' python3 tests/sol-pkill-check.py --binary out/bash --shim "$scratch/pkill-contracts/pkill-intercept.so"
  check 'pkill sanitizer contracts' python3 tests/sol-pkill-check.py --binary "$scratch/pkill-contracts/pkill-sanitize" --sanitizer
  check 'buf probe build' bash tests/sol-buf-build-probe.sh "$scratch/buf-probe"
  check 'buf rollback contracts' env BUF_LOAD_ENV="$scratch/buf-probe/probe.sh" python3 tests/sol-buf-faults.py out/bash
  check 'buf sanitizer contracts' env BUF_LOAD_ENV="$scratch/buf-probe/sanitize.sh" BUF_ASAN_LIB="$(cat "$scratch/buf-probe/asan-runtime.txt")" python3 tests/sol-buf-check.py out/bash
  check 'buf sanitizer rollback contracts' env BUF_LOAD_ENV="$scratch/buf-probe/sanitize.sh" BUF_ASAN_LIB="$(cat "$scratch/buf-probe/asan-runtime.txt")" python3 tests/sol-buf-faults.py out/bash
  check 'top fixture build' env TOP_SKIP_SHELL_BUILD=1 BASHOS_TASK_DIR="$scratch/top-contracts" bash tests/sol-top-build-fixtures.sh
  check 'top private proc and PTY contracts' python3 tests/sol-top-check.py out/bash "$scratch/top-contracts/proc-shim.so"
  check 'top private proc and PTY sanitizer contracts' python3 tests/sol-top-check.py out/bash "$scratch/top-contracts/proc-shim.so" --loader "$scratch/top-contracts/sanitize/load.sh" --asan "$(cat "$scratch/top-contracts/sanitize/asan-path")"
  check 'screen sanitized relay build' bash tests/sol-screen-build-checks.sh "$scratch/screen-checks"
  check 'screen broker native sanitizer' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 "$scratch/screen-checks/native-sanitize"
  check 'screen broker sanitized relay' env TMPDIR=/tmp UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 python3 tests/screen-broker.py --bash out/bash --load-dir "$scratch/screen-checks" --report "$scratch/screen-sanitize.json"
  check 'screen sanitized live streams' env TMPDIR=/tmp UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 python3 tests/sol-screen-streams.py --bash out/bash --load-dir "$scratch/screen-checks" --output "$scratch/screen-streams-sanitize.json"
  check 'ss fixtures build' bash tests/sol-ss-build-fixtures.sh "$scratch/ss-contracts"
  check 'ss numeric snapshots and unaligned netlink remainder' python3 tests/sol-ss-behavior.py --binary out/bash --shim "$scratch/ss-contracts/ss-shim.so" --output "$scratch/ss-native.json"
  check 'ss snapshots under ASan+UBSan' env BASH_ENV="$scratch/ss-contracts/ss-sanitize-env.sh" LD_PRELOAD="$(cat "$scratch/ss-contracts/ss-asan-path")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-ss-behavior.py --binary out/bash --shim "$scratch/ss-contracts/ss-shim.so" --output "$scratch/ss-sanitize.json"
  check 'netstat shared backend after ss remainder fix' python3 tests/sol-netstat-behavior.py --binary out/bash --shim "$scratch/ss-contracts/ss-shim.so" --output "$scratch/ss-netstat-native.json"
  check 'netstat shared backend under ASan+UBSan after ss remainder fix' env BASH_ENV="$scratch/ss-contracts/ss-sanitize-env.sh" LD_PRELOAD="$(cat "$scratch/ss-contracts/ss-asan-path")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-netstat-behavior.py --binary out/bash --shim "$scratch/ss-contracts/ss-shim.so" --output "$scratch/ss-netstat-sanitize.json"
  mkdir -p "$scratch/pgrep-contracts"
  check 'pgrep sanitizer harness build' sh tests/sol-pgrep-tools-build.sh "$scratch/pgrep-contracts"
  check 'pgrep regex and selectors under ASan+UBSan' python3 tests/sol-pgrep-sanitize.py "$scratch/pgrep-contracts/pgrep-sanitize"
  mkdir -p "$scratch/killall-contracts"
  check 'killall guarded signal fixture build' "$CC" -O2 -g -fPIC -shared -U_FORTIFY_SOURCE tests/sol-killall-shim.c -ldl -o "$scratch/killall-contracts/shim.so"
  check 'killall exact selection and owned signals' python3 tests/sol-killall-check.py --binary out/bash --shim "$scratch/killall-contracts/shim.so" --report "$scratch/killall-native.json"
  check 'killall sanitizer module build' env BASHOS_TASK_DIR="$scratch/killall-contracts" bash tests/sol-killall-sanitize-build.sh
  check 'killall guarded sanitizer contracts' env SOL_KILLALL_ASAN="$(cat "$scratch/killall-contracts/asan-runtime.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-killall-check.py --binary out/bash --shim "$scratch/killall-contracts/shim.so" --module "$scratch/killall-contracts/sol-killall-sanitize.so" --report "$scratch/killall-sanitize.json"
  check 'ts combined highlight under ASan+UBSan+LSan' env TS_REQUIRE_NANO_STATUSBAR=1 bash tests/opus-ts-sanitize.sh out/bash
  check 'coreutils dispatcher under ASan+UBSan' env BASHOS_TASK_DIR="$scratch/coreutils-contracts" bash tests/sol-coreutils-sanitize.sh out/bash
  check 'grep sanitizer harness build' bash tests/sol-grep-build-harness.sh "$scratch/grep-contracts"
  check 'grep PCRE2 sanitizer contracts' python3 tests/sol-grep-check.py out/bash --impl "$scratch/grep-contracts"
  check 'ptybroker sanitizer boundaries build' bash tests/sol-ptybroker-build-checks.sh "$scratch/ptybroker-contracts"
  check 'ptybroker native boundaries under ASan+UBSan' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/ptybroker-contracts/native-sanitize"
  check 'ptybroker bounded streams under UBSan' env TMPDIR=/tmp UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-ptybroker-streams.py --bash out/bash --loadable "$scratch/ptybroker-contracts/ptybroker-ubsan.so" --output "$scratch/ptybroker-ubsan.json"
  check 'rsync sanitizer module' bash tests/opus-rsync-so.sh "$scratch/rsync-contracts.so" asan
  check 'rsync push under ASan+UBSan' python3 tests/opus-rsync-check.py out/bash --load "$scratch/rsync-contracts.so" --preload "$($CC -print-file-name=libasan.so)"
  check 'sv fault and sanitizer modules' bash tests/sol-sv-build-fixtures.sh "$scratch/sv-contracts"
  check 'sv native lifecycle and write faults' env SV_TEST_WRITE_SHIM="$scratch/sv-contracts/write-shim.so" python3 tests/sol-sv-check.py out/bash
  check 'sv lifecycle under ASan+UBSan' env BASH_ENV="$scratch/sv-contracts/asan-env.sh" LD_PRELOAD="$(cat "$scratch/sv-contracts/asan-library.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-sv-check.py out/bash
  check 'sv sanitized readiness backpressure' env BASH_ENV="$scratch/sv-contracts/asan-env.sh" LD_PRELOAD="$(cat "$scratch/sv-contracts/asan-library.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/astra-sv-readiness.py out/bash
  mkdir -p "$scratch/rtspcat-contracts"
  check 'RTSP bounded allocation and sanitizer protocol' env BASHOS_TASK_DIR="$scratch/rtspcat-contracts" UBSAN_OPTIONS=halt_on_error=1 bash tests/sol-rtspcat-sanitize.sh
  check 'RTSP sanitized control URI' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/astra-rtspcat-control.py "$scratch/rtspcat-contracts/rtspcat-sanitize" --standalone
  check 'mail sanitizer helpers build' env BASHOS_TASK_DIR="$scratch/mail-contracts" bash tests/sol-mail-sanitize-build.sh
  check 'mail contracts under ASan+UBSan' env SOL_MAIL_LOAD_ENV="$scratch/mail-contracts/sanitize/load.sh" SOL_MAIL_ASAN_LIB="$(cat "$scratch/mail-contracts/sanitize/asan-runtime.txt")" python3 tests/sol-mail-check.py out/bash --timeout 5000
  check 'mail sanitized peer disconnect' env BASH_ENV="$scratch/mail-contracts/sanitize/load.sh" LD_PRELOAD="$(cat "$scratch/mail-contracts/sanitize/asan-runtime.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/astra-mail-disconnect.py out/bash
  check 'netstat fixtures build' bash tests/sol-netstat-build-fixtures.sh "$scratch/netstat-contracts"
  check 'netstat owned sockets and transport fixtures' python3 tests/sol-netstat-behavior.py --binary out/bash --shim "$scratch/netstat-contracts/shim.so" --output "$scratch/netstat-native.json"
  check 'netstat transport under ASan+UBSan' env BASH_ENV="$scratch/netstat-contracts/sanitize-env.sh" LD_PRELOAD="$(cat "$scratch/netstat-contracts/asan-path")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-netstat-behavior.py --binary out/bash --shim "$scratch/netstat-contracts/shim.so" --no-live --output "$scratch/netstat-sanitize.json"
  check 'ping boundary build' bash tests/sol-ping-build.sh "$scratch/ping-contracts"
  check 'ping native echo contracts' python3 tests/sol-ping-check.py out/bash "$scratch/ping-contracts"
  check 'ping injected sanitizer contracts' python3 tests/sol-ping-check.py out/bash "$scratch/ping-contracts" --sanitize
  check 'dmsetup independent ioctl oracle' python3 tests/opus-dmsetup-ioctl.py out/bash
  check 'dmsetup ioctl oracle under ASan+UBSan' bash tests/review-dmsetup-sanitize.sh out/bash
  check 'fstrim fixture build' env BASHOS_TASK_DIR="$scratch/fstrim-contracts" bash tests/opus-fstrim-build.sh
  check 'fstrim native boundary contracts' python3 tests/opus-fstrim-check.py --binary out/bash --module "$scratch/fstrim-contracts/artifacts/fstrim.so"
  check 'fstrim boundary under ASan+UBSan' python3 tests/opus-fstrim-check.py --binary out/bash --module "$scratch/fstrim-contracts/artifacts/fstrim-sanitize.so" --preload "$(cat "$scratch/fstrim-contracts/artifacts/asan-path.txt")"
  check 'fstrim isolated util-linux oracle' env OPUS_FSTRIM_EVIDENCE="$scratch/fstrim-contracts" bash tests/opus-fstrim-oracle.sh out/bash "$scratch/fstrim-contracts/artifacts/fitrim-preload.so"
  check 'hwclock isolated fixture build' env BASHOS_TASK_DIR="$scratch/hwclock-contracts" bash tests/sol-hwclock-build.sh
  check 'hwclock guarded native contracts' python3 tests/sol-hwclock-check.py --binary out/bash --module "$scratch/hwclock-contracts/artifacts/hwclock.so" --report "$scratch/hwclock-native.json"
  check 'hwclock standalone sanitizer contracts' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-hwclock-check.py --binary out/bash --module "$scratch/hwclock-contracts/artifacts/hwclock.so" --host "$scratch/hwclock-contracts/artifacts/hwclock-sanitize" --report "$scratch/hwclock-sanitize.json"
  check 'swapoff boundary build' env BASHOS_TASK_DIR="$scratch/swapoff-contracts" bash tests/sol-swapoff-build.sh
  check 'swapoff native guarded contracts' python3 tests/sol-swapoff-check.py --binary out/bash --shim "$scratch/swapoff-contracts/artifacts/swapoff-shim.so" --output "$scratch/swapoff-native.json"
  check 'swapoff guarded ASan+UBSan contracts' python3 tests/sol-swapoff-check.py --binary out/bash --shim "$scratch/swapoff-contracts/artifacts/swapoff-shim.so" --module "$scratch/swapoff-contracts/artifacts/swapoff-sanitize.so" --asan "$(cat "$scratch/swapoff-contracts/artifacts/asan-path.txt")" --output "$scratch/swapoff-sanitize.json"
  check 'mkfs private fault modules' env BASHOS_TASK_DIR="$scratch/mkfs-contracts" bash tests/sol-mkfs-build.sh
  check 'mkfs native write faults' python3 tests/sol-mkfs-faults.py --binary out/bash --module "$scratch/mkfs-contracts/artifacts/mkfs-shim.so" --report "$scratch/mkfs-faults.json"
  check 'mkfs private images under ASan+UBSan' env PATH="$PATH:/usr/sbin:/sbin" python3 tests/sol-mkfs.py --binary out/bash --module "$scratch/mkfs-contracts/artifacts/mkfs-sanitize.so" --asan-lib "$(cat "$scratch/mkfs-contracts/artifacts/asan-path.txt")" --report "$scratch/mkfs-sanitize.json"
  check 'mkfs write faults under ASan+UBSan' python3 tests/sol-mkfs-faults.py --binary out/bash --module "$scratch/mkfs-contracts/artifacts/mkfs-sanitize.so" --asan-lib "$(cat "$scratch/mkfs-contracts/artifacts/asan-path.txt")" --report "$scratch/mkfs-sanitize-faults.json"
  check 'losetup fixture build' env BASHOS_TASK_DIR="$scratch/losetup-contracts" bash tests/sol-losetup-build.sh "$scratch/losetup-contracts/artifacts"
  check 'losetup native boundary contracts' python3 tests/sol-losetup-fixtures.py --binary out/bash --module "$scratch/losetup-contracts/artifacts/losetup-fixture.so"
  check 'losetup boundary under ASan+UBSan' python3 tests/sol-losetup-fixtures.py --binary out/bash --module "$scratch/losetup-contracts/artifacts/losetup-sanitize.so" --preload "$(cat "$scratch/losetup-contracts/artifacts/libasan-path")"
  check 'fsfreeze fixture build' env BASHOS_TASK_DIR="$scratch/fsfreeze-contracts" bash tests/sol-fsfreeze-build.sh "$scratch/fsfreeze-contracts/artifacts"
  check 'fsfreeze native boundary contracts' python3 tests/sol-fsfreeze-check.py --binary out/bash --module "$scratch/fsfreeze-contracts/artifacts/fsfreeze.so"
  check 'fsfreeze boundary under ASan+UBSan' python3 tests/sol-fsfreeze-check.py --binary out/bash --module "$scratch/fsfreeze-contracts/artifacts/fsfreeze-sanitize.so" --asan-library "$(cat "$scratch/fsfreeze-contracts/artifacts/asan-library.txt")"
  check 'shutdown fail-closed fixture build' env BASHOS_TASK_DIR="$scratch/halt-contracts" bash tests/sol-poweroff-build.sh
  check 'shutdown intercepted native contracts' python3 tests/sol-halt-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so"
  check 'shutdown intercepted sanitizer contracts' python3 tests/sol-halt-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so" --sanitize-dir "$scratch/halt-contracts/artifacts"
  check 'poweroff intercepted native contracts' python3 tests/sol-poweroff-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so"
  check 'poweroff intercepted sanitizer contracts' python3 tests/sol-poweroff-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so" --sanitize-dir "$scratch/halt-contracts/artifacts"
  check 'reboot intercepted native contracts' python3 tests/sol-reboot-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so"
  check 'reboot intercepted sanitizer contracts' python3 tests/sol-reboot-check.py --binary out/bash --shim "$scratch/halt-contracts/artifacts/boundary.so" --sanitize-dir "$scratch/halt-contracts/artifacts"
  check 'rngseed intercepted boundaries build' bash tests/sol-rngseed-build.sh "$scratch/rngseed-contracts"
  check 'rngseed intercepted native faults' env PATH= "$scratch/rngseed-contracts/rngseed-host"
  check 'rngseed intercepted ASan+UBSan faults' env PATH= ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/rngseed-contracts/rngseed-host-sanitize"
  check 'rngseed retained sanitizer assertions' env PATH= ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/rngseed-contracts/rngseed-legacy-sanitize"
  check 'keyctl private fixtures build' env BASHOS_TASK_DIR="$scratch/keyctl-contracts" bash tests/sol-keyctl-build.sh
  check 'keyctl private keyring contracts' python3 tests/sol-keyctl-check.py --binary out/bash --module "$scratch/keyctl-contracts/artifacts/keyctl-shim.so" --report "$scratch/keyctl-native.json"
  check 'keyctl private keyring sanitizer contracts' python3 tests/sol-keyctl-check.py --binary out/bash --module "$scratch/keyctl-contracts/artifacts/keyctl-sanitize.so" --real-module "$scratch/keyctl-contracts/artifacts/keyctl-real-sanitize.so" --preload "$(cat "$scratch/keyctl-contracts/artifacts/asan-path.txt")" --report "$scratch/keyctl-sanitize.json"
  check 'keyctl real private kernel qualification' python3 -c 'import json,sys; reports=[json.load(open(p)) for p in sys.argv[1:]]; assert all(r["kernel"]["status"]=="passed" for r in reports), reports' "$scratch/keyctl-native.json" "$scratch/keyctl-sanitize.json"
  check 'ipcmk owned IPC fixture build' bash tests/sol-ipcmk-build-fixtures.sh "$scratch/ipcmk-contracts" out/bash
  check 'ipcmk owned IPC lifecycle' python3 tests/sol-ipcmk.py out/bash "$scratch/ipcmk-contracts/kernel.so"
  check 'ipcmk standalone sanitizer faults' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/ipcmk-contracts/fixture-sanitize"
  check 'ipcmk owned IPC sanitizer lifecycle' env ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-ipcmk.py "$scratch/ipcmk-contracts/bash-sanitize" "$scratch/ipcmk-contracts/kernel-sanitize.so"
  check 'ipcctl private fixture build' bash tests/sol-ipcctl-build.sh "$scratch/ipcctl-contracts"
  check 'ipcctl private resource contracts' python3 tests/sol-ipcctl-check.py --binary out/bash --module "$scratch/ipcctl-contracts/ipcctl-shim.so" --report "$scratch/ipcctl-native.json"
  check 'ipcctl private resource sanitizer contracts' python3 tests/sol-ipcctl-check.py --binary out/bash --module "$scratch/ipcctl-contracts/ipcctl-shim-sanitize.so" --preload "$(cat "$scratch/ipcctl-contracts/asan-path.txt")" --report "$scratch/ipcctl-sanitize.json"
  check 'ipcctl native prerequisites exercised' python3 -c 'import json,sys; assert all(json.load(open(p))["native"]["status"]=="pass" for p in sys.argv[1:])' "$scratch/ipcctl-native.json" "$scratch/ipcctl-sanitize.json"
  check 'setpgid staged production build' ./build.sh --include setpgid --name setpgid-contracts --no-strip
  check 'setpgid UBSan module build' bash tests/sol-setpgid-build-ubsan.sh "$scratch/setpgid-contracts"
  check 'setpgid owned children under UBSan' env UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-setpgid-check.py --binary out/bash --module "$scratch/setpgid-contracts/setpgid-ubsan.so"
  check 'renice private boundary build' bash tests/sol-renice-build.sh "$scratch/renice-contracts"
  check 'renice owned-child contracts' python3 tests/sol-renice-check.py out/bash "$scratch/renice-contracts/fixture.so"
  check 'renice owned-child sanitizer contracts' env ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 SOL_RENICE_MODULE="$scratch/renice-contracts/renice-sanitized.so" SOL_RENICE_ASAN_RUNTIME="$(cat "$scratch/renice-contracts/asan-runtime")" python3 tests/sol-renice-check.py out/bash "$scratch/renice-contracts/fixture.so"
  check 'zstd fault harness build' "$CC" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables" tests/sol-zstd-host.c -lzstd -ldl -o "$scratch/zstd-contracts"
  check 'zstd streaming faults under ASan+UBSan' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$scratch/zstd-contracts"
  check 'doas private fixture build' python3 tests/sol-doas-build.py "$scratch/doas-native"
  check 'doas delegation and owned-child wait' python3 tests/sol-doas-check.py --fixture "$scratch/doas-native/fixture" --shell out/bash
  check 'doas sanitized fixture build' python3 tests/sol-doas-build.py "$scratch/doas-sanitize" --sanitize
  check 'doas boundaries under ASan+UBSan' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-doas-check.py --fixture "$scratch/doas-sanitize/fixture"
  check 'sudo private fixture build' python3 tests/sol-sudo-build.py "$scratch/sudo-native"
  check 'sudo fixture and shell contracts' python3 tests/sol-sudo-check.py --fixture "$scratch/sudo-native/fixture" --shell out/bash
  check 'sudo native list projection' python3 tests/astra-sudo-list-check.py --shell out/bash --preload "$scratch/sudo-native/list-preload.so"
  check 'sudo sanitized fixture build' python3 tests/sol-sudo-build.py "$scratch/sudo-sanitize" --sanitize
  check 'sudo boundaries under ASan+UBSan' env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 python3 tests/sol-sudo-check.py --fixture "$scratch/sudo-sanitize/fixture"
  check 'sudo namespace final smoke' python3 tests/sol-sudo-userns.py --shell out/bash --final-smoke --report "$scratch/sudo-userns.json"
  check 'payload module build' bash tests/opus-payload-build-sanitizer.sh "$scratch/payload-contracts"
  check 'payload protocol under ASan+UBSan' python3 tests/opus-payload-installer.py out/bash --module "$scratch/payload-contracts/payload-sanitize.so" --asan-runtime "$(cat "$scratch/payload-contracts/libasan.path")"
  check 'cluster staged production build' ./build.sh --include cluster --name cluster-contracts --no-strip
  check 'cluster module build' bash tests/sol-cluster-sanitizer-build.sh "$scratch/cluster-contracts"
  check 'cluster membership under ASan+UBSan' env BASHOS_CLUSTER_TEST_MODULE="$scratch/cluster-contracts/cluster-sanitized.so" LD_PRELOAD="$(cat "$scratch/cluster-contracts/asan-runtime.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-cluster-membership.py out/bash
  check 'join stream ownership under ASan+UBSan' bash tests/review-join-sanitize.sh out/bash
  check 'nl native and fallback modules' bash tests/sol-nl-build-modules.sh "$scratch/nl-contracts"
  for mode in native fallback; do
    for suite in nl-parity sol-nl-check review-nl-backrefs; do
      check "nl $mode $suite under ASan+UBSan" env NL_MODULE="$scratch/nl-contracts/nl-$mode-sanitized.so" LD_PRELOAD="$(cat "$scratch/nl-contracts/asan-path.txt")" ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 "tests/$suite.py" out/bash
    done
  done
  check 'head complete options under ASan+UBSan' env BASHOS_TASK_DIR="$scratch/head-contracts" bash tests/sol-head-sanitize.sh out/bash
  check 'PCRE contract module build' env BASHOS_TASK_DIR="$scratch/pcre-contracts" bash tests/sol-pcre-sanitize-build.sh
  check 'PCRE contracts under ASan+UBSan' env SOL_PCRE_LOAD_ENV="$scratch/pcre-contracts/sanitize/load.sh" SOL_PCRE_ASAN_LIB="$(cat "$scratch/pcre-contracts/sanitize/asan-runtime.txt")" python3 tests/sol-pcre-check.py out/bash
  check 'diff allocation fixture build' bash tests/sol-diff-build.sh "$scratch/diff" out/bash
  check 'diff allocation failures' python3 tests/sol-diff-alloc.py "$scratch/diff/bash-native"
  check 'diff allocation failures under ASan+UBSan' python3 tests/sol-diff-alloc.py "$scratch/diff/bash-sanitize"
  check 'wc locale contracts under ASan+UBSan' bash tests/sol-wc-sanitize.sh out/bash
  check 'unexpand under ASan+UBSan' bash tests/sol-unexpand-sanitize.sh out/bash
  check 'crypto independent contracts under ASan+UBSan' env BASHOS_TASK_DIR="$scratch/crypto-contracts" bash tests/sol-crypto-sanitize.sh out/bash
  check 'P-256 and ACME under ASan+UBSan' bash tests/p256-sanitize.sh out/bash
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
  check 'sed under ASan+UBSan' bash tests/sol-sed-sanitize.sh out/bash
  check 'procstat under ASan+UBSan' bash tests/procstat-sanitize.sh out/bash
  check 'helper modules under ASan+UBSan' bash tests/helper-sanitize.sh out/bash
  check 'final modules under ASan+UBSan' bash tests/final-sanitize.sh out/bash
  check 'large modules under ASan+UBSan' bash tests/large-sanitize.sh out/bash
  check 'terminal modules under ASan+UBSan' bash tests/terminal-sanitize.sh out/bash
  check 'nano combined selftests and PTYs under ASan+UBSan' env NANO_REQUIRE_RESOLVED_TS=1 bash tests/opus-nano-sanitize.sh out/bash
  check 'terminal and buffer edges under ASan+UBSan' bash tests/vt-buf-sanitize.sh out/bash
  check 'graphics under ASan+UBSan' bash tests/gpu-sanitize.sh out/bash
  check 'git under ASan+UBSan' bash tests/git-sanitize.sh out/bash
  check 'index under ASan+UBSan' bash tests/sol-index-sanitize.sh out/bash
  check 'uclampset under ASan+UBSan' bash tests/sol-uclampset-sanitize.sh out/bash
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
  if "$CC" -O1 -g -fsanitize=address,undefined "${INC[@]}" loadables/grep.c tests/grep-host.c -lpcre2-8 -o "$scratch/grep"; then
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
