# blockdev software-path qualification

`blockdev` applies all leading actions, in order, to each following device
operand. `--` ends option parsing. An open or ioctl failure sets exit status 1;
processing continues with later actions and operands. Invalid options or missing
actions/devices return 2 before opening anything. Help and version return 0
unless writing their output fails.

The action list now uses the original Bash argument list, removing the old
silent truncation after 32 actions. Query, help and version output is flushed
and checked before returning. A failed write returns 1 and clears the stream
error so a later invocation can succeed. Close failures also return 1, and
opened descriptors use `O_CLOEXEC`. The legacy `--getsize` option is included
in help and usage.

## Coverage

`tests/sol-blockdev-shim.c` includes the genuine production source with only
`open`, `ioctl`, and `close` renamed to private fixture functions. Those functions
never forward to host device syscalls. Unexpected paths fail with `ENOENT`;
setters only change fixture metadata in memory. This is a test-only module,
with no environment-controlled interception in the shipped builtin.

`tests/sol-blockdev-check.py` loads the module into the targeted Bash executable
and uses an empty `PATH`. Its independent metadata and request oracle covers:

- All ten advertised actions, separately and together on two devices, with exact
  request traces and setter values, in device-major/action-minor order.
- `BLKGETSIZE64` in bytes and divided by 512 (including a size above 32-bit
  sector range, a remainder, and a size below one sector); the distinct legacy
  `BLKGETSIZE` result; logical sector size, block size, and normalized RO state.
- Setro/setrw state across actions and separate invocations; flush and reread
  requests with zero arguments; more than 32 actions.
- Missing actions/operands, unknown/malformed options, an empty device name,
  explicit `--`, and options appearing after the first device operand.
- EIO, ENOTTY and EPERM for every action, continuation to later actions/devices,
  exact descriptor cleanup, open failures, the EACCES read-write retry, and
  close failure handling.
- `/dev/full` output errors for queries/help/version followed by recovery in
  the same shell, 200 repeated successful calls, and 100 repeated failed ioctl batches with no
  outstanding fixture handles.
- The unmodified native open/ioctl path on a private regular file, checking
  ENOTTY and real descriptor counts over 100 failed queries. No native mutation
  request is issued.

Build the targeted binary first, then build the normal and ASan/UBSan fixture
modules. `GATE` below names the campaign resource wrapper; both compilation
steps must use its build gate. Tests themselves do not compile anything.

```sh
python3 "$GATE" build -- ./build.sh --include blockdev --name sol-blockdev
python3 "$GATE" build -- bash tests/sol-blockdev-build.sh
python3 tests/sol-blockdev-check.py --binary out/bash-sol-blockdev \
  --module "$BASHOS_TASK_DIR/artifacts/blockdev.so"
python3 tests/sol-blockdev-check.py --binary out/bash-sol-blockdev \
  --module "$BASHOS_TASK_DIR/artifacts/blockdev-sanitize.so" \
  --preload "$(cat "$BASHOS_TASK_DIR/artifacts/asan-path.txt")"
```

All 66 cases pass against the corrected normal module and the ASan/UBSan
module. The baseline source, compiled with the same normal shim harness and
compiler flags, passes 60 and fails six: action truncation, ignored close
failure, query/help/version output failures, and the missing `--getsize` help
entry. These checks retain the same expected values for both versions.
Sanitizers instrument the fixture module and included production source;
Bash itself is the normal targeted executable. LeakSanitizer is disabled;
fixture handle counts and native descriptor counts are checked explicitly.

There are no required companion loadables or shared-helper changes.
`--include blockdev` selects only this command; build selection automatically
stages the repository's default `_jsmn` helper.

## Measurement scope

`bench/sol-blockdev.py` times the normal fixture module, using one warm-up and
at least seven samples on the single CPU inherited from the bench gate. Each
sample starts a fresh shell and reloads identical fixture metadata. Every
invocation must succeed, and the complete output, final fixture state, exact
open/close/ioctl counts, and absence of leaked/invalid handles are checked on
every sample, including warm-up. Tracing is disabled for measurement.

The fixed default work units are:

| Batch | Invocations | Devices per invocation | Opens/closes | Ioctls | Query output records |
| --- | ---: | ---: | ---: | ---: | ---: |
| Six queries | 1,000 | 2 | 2,000 each | 12,000 | 12,000 |
| RO query/setro/query/setrw/query/flush/reread | 1,000 | 2 | 2,000 each | 14,000 | 6,000 |

Timings include shell startup, module loading, fixture initialization, shell
loop execution, captured output, and in-memory syscall shims. They do not
measure kernel/device latency or represent an external-tool speed comparison.
Each request invocation restores both devices to read-write fixture state;
the first invocation's initially nonzero RO metadata has a separate oracle.
The raw JSON records every sample, validation result, affinity, versions,
source/binary/module/fixture hashes, and work counts.

```sh
python3 "$GATE" bench -- python3 bench/sol-blockdev.py \
  --binary out/bash-sol-blockdev \
  --module "$BASHOS_TASK_DIR/artifacts/blockdev.so" \
  --passes 1000 --runs 7 --output "$BASHOS_TASK_DIR/benchmark.json"
```

This qualifies the software paths against the Linux ioctl API boundary.
Actual block-device behavior, privilege checks, driver-specific errors, flush
latency and partition-table reread effects require separate hardware
qualification. No host block device is opened or changed by these checks or
measurements. No claim of real-device qualification or performance is made.

## Recorded result (2026-10-19)

Both batches passed every validation on CPU 11, with seven samples after one
warm-up. The source, fixture and binary hashes and full environment are in
`$BASHOS_TASK_DIR/benchmark.json`; sample times below are milliseconds.

| Batch | Median ms | Min–max ms | Seven samples, ms |
| --- | ---: | ---: | --- |
| queries | 25.369 | 21.653–27.345 | 27.345, 25.658, 25.369, 24.068, 24.644, 26.667, 21.653 |
| requests | 19.920 | 17.395–21.816 | 17.395, 19.920, 20.851, 21.816, 19.553, 18.134, 21.466 |

These are separate syscall-shim work units. There is no external ratio,
before/after speedup claim, or real-device measurement.
