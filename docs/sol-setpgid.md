# setpgid: owned-child behavior and API timing

`setpgid pid pgrpid` wraps the stock Bash `examples/loadables/setpgid.c`
system-call implementation. Exactly two operands are required. PID zero selects
the calling shell; PGID zero makes the target process its own group leader.
Explicit IDs and zero defaults have the same kernel semantics. Success is silent.
The target must be the caller or an unexecuted child in the same session.
Session leaders cannot change groups. Existing same-session groups can be joined;
a nonexistent group other than the target's PID is rejected by the kernel.

The repository stock patch `patches/setpgid-ids.patch` rejects values that do not
fit `pid_t` before calling the kernel, and rejects trailing operands. Previously,
on Linux with 32-bit `pid_t`, `4294967296` narrowed to zero: an invalid PID could
silently select the caller, and an invalid PGID could create a new group.
Negative and nonnumeric IDs already failed. Intmax overflow already failed.
The build registers this fix through `config/stock-patches.json`; the upstream
example and generated build tree are not maintained as replacement sources.
No common helper changes or companion loadables are needed.

## Focused checks

```sh
# Run each compilation through your resource gate.
./build.sh --include setpgid --name sol-setpgid
bash tests/sol-setpgid-build-ubsan.sh /tmp/setpgid-check
# These checks do not compile.
python3 tests/sol-setpgid-check.py --binary out/bash-sol-setpgid
python3 tests/sol-setpgid-check.py --binary out/bash-sol-setpgid \
  --module /tmp/setpgid-check/setpgid-ubsan.so
```

The Linux test uses a persistent noninteractive shell with empty `PATH` and job
control disabled. All mutation targets are that shell or its own coprocesses.
Python queries `os.getpgid`/`os.getsid` independently of the loadable. It verifies
all four explicit/zero PID/PGID combinations, repeated owned-child moves into
its own and the inherited group, exact reset state, invalid/overflowing IDs,
arity, missing and reaped children, nonchild ESRCH, nonexistent-group EPERM,
session-leader and cross-session EPERM, and executed-child EACCES. A private
session is created only for the Popen-owned session-leader test. Normal tests
never change another process's group or send a group signal. Child input is
released and each child reaped. Repeated lifecycle checks assert stable shell
FD counts and group state. Silent success is checked even with stdout directed
to `/dev/full`. The UBSan module compiles the actual staged production source
and runs the same real-kernel tests, including invalid input recovery.

The missing PID is above Linux's configured `pid_max`. Integer boundaries in
this test target Linux's 32-bit `pid_t`. These fixtures qualify the software
path on Linux; they do not claim cross-platform errno precedence. No hardware
or privileged operation is required.

## Measurement method

`bench/sol-setpgid.py --binary out/bash-sol-setpgid --output REPORT.json` must
run through the benchmark resource gate, with builds completed separately.
The driver requires one pinned CPU, a warm-up and at least seven samples.
It records all sample durations, options, reset rules, source/fixture/binary
SHA-256 values, tool versions, CPU affinity and environment.

Each operation sample moves an already-created blocked owned child alternately
into a group with its own PID and back into the inherited group. Every call
must return success with no output or diagnostic, and Python checks the exact
resulting group after every operation. Shell state and FD counts must remain
stable. Child creation and cleanup are outside the operation interval.
The builtin interval includes request/reply pipe traffic, shell parsing and
Python's independent group assertions. This is an API/control-path measurement,
not isolated syscall latency.

A separate lifecycle workload measures shell startup, builtin verification,
coprocess creation, PID exchange, independent group inspection, release, wait
and shell exit, with **zero setpgid calls**. Python `os.setpgid` on its own
blocked child is reported separately with the same alternating group oracle;
its interpreter and control overhead differs. Neither reference is an external
command implementing this CLI, and the report publishes no external ratio or
speedup claim. There was no historical validated timing for this command and
no evidence supporting a speculative performance optimization.

## Validation results

The stock baseline passed 26 cases and failed seven: trailing operands and two
zero-wrapping IDs incorrectly succeeded and changed the shell's group; four
other oversized IDs reached the kernel after narrowing instead of receiving a
range diagnostic. The fixed native builtin and the production-source UBSan
module each passed all 33 cases with no sanitizer diagnostic. These results
include exact group assertions after 80 repeated child moves, 30 child
lifecycles with stable FD counts, and recovery after each invalid input.

## Timing results

Bash 5.3.15, GCC 14.2.0, Python 3.13.5, Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, Linux 6.12.111+deb13-amd64. The run was pinned to CPU 11, with one warm-up and seven measured samples per workload. All three case statuses are `pass`.

| Workload | Units/sample | Sample min / median / max (ms) | Median per unit |
|---|---:|---:|---:|
| Builtin moves + IPC + group oracle | 4000 | 231.681 / 296.400 / 338.504 | 74.100 µs |
| Python API moves + group oracle | 4000 | 2.307 / 2.623 / 2.788 | 0.656 µs |
| Shell and child lifecycle (zero moves) | 40 | 129.802 / 141.723 / 154.223 | 3.543 ms |

The builtin figure includes the full control protocol and is not a syscall-only estimate. The separate creation/lifecycle figure is not subtracted from it. These measurements establish a validated API baseline; they do not establish an external-command or before/after speedup. The task receipt preserves all raw samples and metadata in `benchmark-v1.json`, alongside the native/UBSan logs and gate receipts.

Measured binary SHA-256: `4493b8e4e84e20becd22656a7a39c9c8165a2b5bc686e412a3b5afc6a04af037`.
