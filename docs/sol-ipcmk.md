# ipcmk creation checks

`ipcmk` creates one System V object (`-M SIZE`, `-S COUNT`, or `-Q`) or one
named POSIX object (`-m SIZE`, `-s`, or `-q` with `-n /name`). It retains the
existing single-resource-per-call contract, default mode 0644, binary size
suffixes K/KiB through T/TiB, and attached/long option forms. Successful objects
persist until their owner removes them. POSIX semaphores start at zero; POSIX
message queues use the kernel's default attributes. POSIX permissions respect
the calling shell's umask. System V mode bits are passed directly to the kernel.

POSIX creation uses exclusive creation and never takes ownership of an existing
name. Shared memory is resized with `ftruncate`, with an explicit `off_t` range
check. Local descriptors and semaphore mappings are closed before returning.
Failures after creation unlink/remove the owned object, including a failed
write or flush of its identifier. Diagnostics preserve the actual kernel error
rather than asserting that every machine lacks POSIX IPC. Numeric arguments
reject signs, whitespace, zero sizes/counts, overflow, and out-of-range modes.

The implementation has no command-owned heap allocations. The fault fixture
executes production code with ENOMEM injected at each of its six creation APIs,
plus ENOSPC, EACCES and ENOSYS, and checks the requested keys, flags, sizes,
counts and permissions. It also checks truncate/close failures and output
rollback against real owned objects. These injected failures do not change
host policy or exhaust global IPC resources.

`tests/sol-ipcmk.py BINARY ORACLE.so` checks all six resource types with an empty
PATH. A test-only loadable reads each exact output record, independently queries
kernel metadata, checks ownership and requested properties, removes the object,
and verifies absence. It exercises modes 0600/0640/0644/0660/0700, POSIX umask,
exclusive-name collisions, forty repeated calls per type, descriptor stability,
parser errors and bounds, aliases, help/version, output-error recovery, and
`ipcctl`'s explicit cleanup policy. Names include the private shell PID and test
resource type. No unrelated object is enumerated or removed.

Build the command and fixtures separately from measurements:

```sh
python3 "$GATE" build -- bash -c './build.sh --include ipcmk,ipcctl --name sol-ipcmk && bash tests/sol-ipcmk-build-fixtures.sh "$BASHOS_TASK_DIR/fixtures"'
python3 tests/sol-ipcmk.py out/bash-sol-ipcmk "$BASHOS_TASK_DIR/fixtures/kernel.so"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$BASHOS_TASK_DIR/fixtures/fixture-sanitize"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-ipcmk.py "$BASHOS_TASK_DIR/fixtures/bash-sanitize" "$BASHOS_TASK_DIR/fixtures/kernel-sanitize.so"
python3 "$GATE" bench -- python3 bench/sol-ipcmk.py --binary out/bash-sol-ipcmk --oracle "$BASHOS_TASK_DIR/fixtures/kernel.so" --samples 7 --passes 200 --output "$BASHOS_TASK_DIR/creation.json"
```

`GATE` denotes the campaign's `scripts/gated.py`. Fixture compilation never runs
inside the correctness or benchmark drivers. `ipcctl` is an explicit companion
for the focused native cleanup check; neither command needs a common helper in
`config/helpers.json`. Modern glibc provides POSIX IPC symbols in libc; fixture
builds also specify `-lrt -pthread`. Older libc targets need those link flags
supplied by the caller and must be qualified separately.

The benchmark measures a fixed batch of 200 create/inspect/remove/absence cycles
per resource type in one shell after one warm-up, followed by seven samples on
one recorded CPU. Every repeated pass validates the output, exit status,
properties and cleanup. The measurements include shell, temporary-file output,
and test-oracle overhead. They are self timings with an independent kernel
oracle; they do not claim an external-tool ratio or a speedup over the formerly
unmeasured implementation. The report records distributions, hashes, options,
work counts, tool versions, environment and IPC limits.

Kernel restrictions remain runtime conditions: System V semaphore counts are
bounded by SEMMSL, object totals by IPC namespace limits, and shared-memory sizes
by SHMMAX/address width. POSIX queues also depend on kernel support, queue limits
and RLIMIT_MSGQUEUE; POSIX shared memory and semaphores require a usable backing
mount. ENOSYS/EACCES/ENOMEM/ENOSPC outcomes are failures, never counted as passing
creation coverage or assigned successful timing. This task qualifies the Linux
software paths on the recorded host; it does not claim other libc/architecture
or kernel-policy configurations were exercised.

## Validated run, 2026-10-19

The targeted optimized build and all fixture compilations passed. The native
and ASan/UBSan real-kernel suites passed all six resource types and 57 invalid
input cases. The standalone ASan/UBSan fixture passed all injected allocation,
policy, close, truncate and output failures with no sanitizer findings. An
initial test-only parse error in the companion cleanup check was corrected;
the two known test queues were removed, and both complete suites passed again.

Seven measured batches after one warm-up, each containing 200 validated cycles,
ran on CPU 11, Linux 6.12.111+deb13-amd64, x86-64, GCC 14.2.0, Bash 5.3.15.
All 9,600 creations across warm-up and measured batches passed their independent
checks and cleanup; no normal workload was restricted. Values below are
microseconds per validated creation/inspection/removal cycle, with shell
startup and file/oracle overhead included.

| Resource | Minimum | Median | Maximum |
|---|---:|---:|---:|
| shm | 60.13 | 60.92 | 61.77 |
| sem | 55.44 | 58.44 | 60.37 |
| msg | 56.24 | 56.60 | 58.47 |
| posix-shm | 74.15 | 74.62 | 75.68 |
| posix-sem | 105.95 | 113.08 | 117.50 |
| posix-msg | 79.69 | 82.39 | 84.01 |

The separate kernel-bound probes returned EINVAL for a parser-valid INT_MAX
semaphore count (host SEMMSL 32,000) and SIZE_MAX shared-memory request
(host SHMMAX 18,446,744,073,692,774,399). Those are labeled kernel rejections,
not parser failures or successful creation timings. POSIX queue defaults were
10 messages of 8,192 bytes, with RLIMIT_MSGQUEUE 819,200 bytes.

The raw report is `creation.json` in the task evidence directory alongside
`environment.json`, exact command/status receipts, original failed test logs,
corrected passing logs and sanitizer logs. The optimized binary SHA-256 is
`a86531939b34250ed0994ff7daf3397ecc12207a0bbbcdffaaf1113cb1bdffe4`;
the production source SHA-256 is
`be5b000a3142e83cb120e71e1d6f12756660a327d36d1f7b4622f2c3cba44f1e`.
Source hashes match the staged build input and final files. Historical
catalog reports were not changed.
