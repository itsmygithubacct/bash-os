# poweroff software-path validation

`poweroff` dispatches `reboot(RB_POWER_OFF)` through
`loadables/common/reboot-impl.h`. The preceding halt changes already implement
operand rejection, Bash help, dry-run write-error handling, and syscall return
handling. This work validates that implementation without changing the shared
header. The existing Bash-OS contract remains: `-f` skips sync, `-n` reports a
dry run, and their combination never requests shutdown. These meanings differ
from other shutdown utilities.

The wrapper calls the kernel directly. It does not change runlevel, override
privileges, or write accounting records. Kernel permission failures propagate
as status 1, including with `-f`. Unsupported flags and operands return status 2
before sync or shutdown. Help uses Bash's status-2 convention.

## Coverage and safety boundary

All calls execute genuine production code behind the existing
`tests/sol-halt-shim.c` interceptor. It replaces reboot, sync and the accounting
entry points without forwarding to the host. No live shutdown, sync or
accounting operation is used. Empty `PATH` is set in every test shell.

The retained `tests/sol-halt-check.py` suite passes 108 checks covering all
three siblings: dispatch constants, call ordering, flags, parsing, help,
EPERM/EACCES/EINVAL/EIO/ENOSYS, output failures and recovery, repeated calls,
shell state and descriptor preservation.

`tests/sol-poweroff-check.py` adds 94 checks:

- All 62 `f`/`n` option clusters of lengths one through five.
- Twenty-five operand cases after `--`, including empty strings, whitespace,
  newlines and option-looking operands.
- Six unsupported option forms.
- A single persistent shell executing 2,800 mixed poweroff/halt/reboot calls,
  alternating dry run, parser rejection, permission errors, ordinary and forced
  success, and help. Every call has an independently expected status and exact
  sync/shutdown/accounting trace.

All 202 checks pass natively and with ASan/UBSan. The task-owned module builder
uses `-Wl,-Bsymbolic-functions` so each module's builtin structure refers to its
instrumented entry point even when the shell exports the same symbol. Undefined
reboot and sync references still resolve to the preload interceptor. ELF
inspection verifies instrumentation and local entry-point binding. Leak checking
is disabled for these modules loaded into an unsanitized Bash host; the retained
suite separately checks descriptor counts and caller-owned descriptors.

## Reproduction

There are no required companion commands in `config/helpers.json`. Build
`poweroff,halt,reboot` to include the sibling regression targets. During the
completion campaign, run both compilation commands through the build gate:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include poweroff,halt,reboot --name sol-poweroff
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  bash tests/sol-poweroff-build.sh
```

Set `BASHOS_TASK_DIR` to the evidence directory before the fixture build.
The following commands do not compile:

```sh
python3 tests/sol-halt-check.py --binary out/bash-sol-poweroff \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so"
python3 tests/sol-poweroff-check.py --binary out/bash-sol-poweroff \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so"
```

Repeat both with `--sanitize-dir "$BASHOS_TASK_DIR/artifacts"` for ASan/UBSan.

## Measurement scope

`bench/sol-poweroff.py` measures four workloads: ordinary and forced requests
returning success, and ordinary and forced requests returning EPERM. Every
request is intercepted. Each batch contains 10,000 calls, with an independent
expected status and exact boundary trace for each call. The interceptor resets
before each request; a fresh shell starts each batch. One validated warm-up
precedes seven measured samples per workload, pinned to the gate-selected CPU.

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-poweroff.py --binary out/bash-sol-poweroff \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so" --runs 7 --passes 10000 \
  --output "$BASHOS_TASK_DIR/benchmark.json"
```

Reports record every sample's validation, distribution, source and binary
SHA-256, fixture/script/expected-output hashes, options, reset rules, compiler,
Python, Bash and libc versions, host details and CPU affinity. Times include
shell startup, loop, interceptor reset, status assertions, trace output and
capture. No matched external reference is used because this fixture and the
Bash-OS option contract do not represent an equivalent external shutdown
workload. There is no speedup claim or performance change.

The validated run on CPU 11 produced the following batch distributions
(milliseconds per 10,000 requests; one warm-up and seven measured samples):

| Intercepted request | Median ms | Min–max ms |
|---|---:|---:|
| Sync then success | 244.227 | 220.616–267.316 |
| Forced success | 257.123 | 224.312–280.608 |
| Sync then EPERM | 461.714 | 416.844–498.766 |
| Forced EPERM | 499.232 | 469.887–630.657 |

All four warm-ups and all 28 measured batches passed validation. The shell
binary SHA-256 was
`b0ce2d72cb75acce034444a144a2b5514fa732f25262b1eae32ffe44dcee4858`.
The raw report and logs are preserved in the task evidence directory rather
than replacing historical benchmark data.

These are syscall-shim request timings, **not actual shutdown latency**.
Live kernel privilege enforcement, physical shutdown, storage flush completion,
init integration and non-Linux platforms remain outside this completed software
boundary scope. Integration should retain that qualification and rerun both
suites after any subsequent shared-header change.
