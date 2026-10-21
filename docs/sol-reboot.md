# Reboot software-path validation

`reboot` calls `reboot(RB_AUTOBOOT)` through the shared
`loadables/common/reboot-impl.h`. The preceding halt changes already implement
operand rejection, Bash help, dry-run write-error handling and syscall return
handling. This task validates those changes and the subsequent poweroff fixture
fix without changing production code or the shared header.

The advertised Bash-OS contract is `reboot [-f] [-n]`: `-f` skips sync, and
`-n` reports a dry run. Both flags together still perform no mutation. These
meanings differ from other reboot utilities. The builtin makes a direct kernel
request, without changing runlevel or writing wtmp/accounting records. It does
not bypass kernel privileges: syscall errors return status 1 with the errno
message. Invalid arguments return status 2 before any sync or reboot request.
Bash `--help` returns status 2.

## Coverage and boundary

All invocations execute genuine production code with an empty `PATH`, behind
`tests/sol-halt-shim.c`. That interceptor replaces reboot, sync, updwtmp,
updwtmpx, pututline and pututxline without forwarding to the host. Tests assert
zero accounting calls, the exact reboot command, sync count and call order.
No real reboot, sync, accounting write or service command is invoked.

`tests/sol-reboot-check.py` adds 209 checks:

- A fail-closed guard: ld.so ignores an LD_PRELOAD object it cannot load and
  continues, while `enable -f` would still load the fixture privately. Every
  reboot script, including benchmark batches, first confirms that the
  interceptor (and ASan runtime) were mapped at startup and exits 93 before
  `enable` otherwise; one check asserts that an unpreloaded shell stops there.
- All 170 partitions of `f`/`n` strings of lengths one through four into
  clustered or separate option words, followed by `--`.
- Twenty-three invalid argument/action forms, including empty operands,
  whitespace, newlines, action words, options after operands, and unsupported
  short/long options.
- Fourteen errno/recovery checks: EPERM, EACCES, EINVAL, EIO, ENOSYS, EBUSY and
  EINTR, with and without sync, immediately followed by successful reboot
  dispatch in the same shell.
- A persistent shell running 900 alternating dry, invalid, help, failed,
  ordinary and forced invocations, with exact status/output/trace per call.

The retained halt suite supplies 108 checks across halt/reboot/poweroff,
including `/dev/full`, closed stdout, output recovery, shell state and descriptor
preservation. The retained poweroff suite supplies 94 checks including 2,800
mixed sibling calls. All 411 checks pass natively and all 411 pass with
ASan/UBSan. Artifact inspection confirms sanitizer instrumentation, local builtin
binding and interposable reboot/sync symbols. Run all three suites after
subsequent shared-header edits.

## Reproduction

`config/helpers.json` requires no companion loadables for reboot. Select halt
and poweroff explicitly for shared-wrapper regressions. Compilation is separate
from correctness and timing. During the completion campaign, use the gates:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include reboot,halt,poweroff --name sol-reboot
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  bash tests/sol-poweroff-build.sh
```

Set `BASHOS_TASK_DIR` to the evidence directory for the fixture build. The
existing poweroff builder compiles the interceptor and all three ASan/UBSan
modules. It binds each module's builtin structure to its own instrumented entry
point using `-Wl,-Bsymbolic-functions`; undefined syscall symbols still resolve
to the interceptor. Leak detection is disabled in the unsanitized Bash host;
caller-owned descriptors and descriptor counts are checked separately.

The following checks do not compile:

```sh
for suite in halt poweroff reboot; do
  python3 "tests/sol-$suite-check.py" --binary out/bash-sol-reboot \
    --shim "$BASHOS_TASK_DIR/artifacts/boundary.so"
  python3 "tests/sol-$suite-check.py" --binary out/bash-sol-reboot \
    --shim "$BASHOS_TASK_DIR/artifacts/boundary.so" \
    --sanitize-dir "$BASHOS_TASK_DIR/artifacts"
done
```

## Measurement

`bench/sol-reboot.py` measures ordinary and forced successful dispatch,
ordinary and forced EPERM, dry run, forced dry run and invalid action parsing.
Each batch contains 10,000 invocations with an independent expected status,
output and exact syscall trace for every call. One validated warm-up precedes
seven samples for each workload, pinned to one CPU by the benchmark gate.
The interceptor resets before each call and each batch starts a fresh shell.

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-reboot.py --binary out/bash-sol-reboot \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so" --runs 7 --passes 10000 \
  --output "$BASHOS_TASK_DIR/benchmark.json"
```

The report includes all sample validations and distributions, source/binary/shim
SHA-256, script and expected-output hashes, options, reset rules, work counts,
CPU affinity, and compiler/Python/Bash/libc/kernel versions. Times include shell
startup, loop, reset, assertions, trace output and capture. Expected failure
diagnostics are redirected to `/dev/null` during timing; errno messages are
validated by the correctness suites. There is no matched
external reference or speedup ratio: the fixture and Bash-OS flag meanings do
not represent an equivalent external reboot workload. No previous reboot timing
or reproducible performance bottleneck justified a production optimization.

The validated run on CPU 11 produced these batch distributions
(milliseconds per 10,000 invocations):

| Workload | Median ms | Min–max ms |
|---|---:|---:|
| sync-success | 527.210 | 447.046–624.863 |
| force-success | 491.185 | 457.515–569.204 |
| sync-EPERM | 613.949 | 540.703–639.923 |
| force-EPERM | 772.030 | 623.205–853.814 |
| dry | 400.395 | 363.401–423.714 |
| force-dry | 344.665 | 319.778–381.026 |
| invalid-action | 504.472 | 485.401–541.246 |

All seven warm-ups and 49 measured batches passed exact validation (560,000
invocations). The shell binary SHA-256 was
`9c391bcb7cdf7959c349ff96abe8287b2e0059eebe4046b6ddf8680ec835a61c`.
Raw samples and logs remain in the task evidence directory; historical reports
are unchanged. These distributions describe this run under the campaign gate,
not an isolated maximum-throughput measurement.

Hardware reboot latency remains unmeasured. Actual kernel capability enforcement,
physical restart, storage flush completion, init/service integration and non-Linux
platforms are outside this fixture-backed software-path qualification. Successful
shim returns exercise return handling; they do not prove a real reboot completes.
