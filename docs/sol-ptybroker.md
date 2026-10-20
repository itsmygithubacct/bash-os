# Private PTY stream verification

The task-owned harness extends [the broker contract](ptybroker.md) with fixed,
verified workloads. It runs production `ptybroker` services, uses private PTYs,
and adopts orphaned brokers as a subreaper so that cleanup can be checked by PID
and process start time. Every case terminates its service, reaps its children,
and fails if cleanup needs an emergency kill. No existing session or terminal
is used.

Run the correctness checks against a build containing `ptybroker`:

```sh
TMPDIR=/tmp python3 tests/sol-ptybroker-streams.py --bash out/bash-sol-ptybroker --output /tmp/streams.json
```

The stream cases are:

| Workload | Fixed work and oracle |
| --- | --- |
| Binary relay | 2 MiB + 719 bytes sent through repeated `send-fd` calls in one shell with a 16 KiB window (receive each chunk before sending the next), echoed by a raw child, compared byte for byte at the controller. |
| Burst with observers | 4 MiB generated at the child in 16 KiB blocks with a requested 250 microsecond delay after each block, three active subscribers (one controller and two observers), and one nonreading observer; 64 KiB windows wait for all active readers; each active subscriber must receive every byte at contiguous offsets. The nonreading observer must be disconnected. |
| Sustained output | 8 MiB in 8 KiB blocks, with a 1 ms requested delay after each block, delivered to a controller and observer in 64 KiB windows, waiting for both after each window. Delay scheduling is part of the workload, not a maximum-throughput test. |
| Round trip | 64 serial requests of 256 binary bytes in one attachment; each acknowledgement follows complete PTY output delivery. |
| Input saturation | Stop only the owned raw child, fill the input ring until rejection, resume the child (echoing in 4 KiB blocks with a 500 microsecond delay), verify exactly the accepted bytes, and verify renewed acceptance after drain and wrap. Failed sends are never retried. |

All payloads include NUL and high-bit bytes. Expected content comes from a fixed
65,536-byte arithmetic pattern, independent of observed output; every pass
checks exact bytes and offsets. Burst and sustained cases compare the exact
1 MiB history suffix, reconnect, check the reported gap range, and verify a
new 8 KiB live stream begins at the old `next` offset without replay. Each
stream asserts a broker RSS high-water mark below 32 MiB. This is a generous
regression ceiling for this build, not a claim that kernel socket buffers or
subscriber/fixture processes are included in broker RSS.

Additional checks cover an observer attempting to inject input through its
subscription, invalid scalar bindings, receive arguments and output FDs,
64 attach/detach cycles without descriptor growth, and metadata writes to a
full output device. Workload shells use an empty executable `PATH`; child
fixtures use explicit executable paths.

`tests/sol-ptybroker-native.c` includes the production server implementation.
It tests the exact 1 MiB input boundary (including atomic rejection and a
wrapped tail), the exact 256 KiB subscriber output boundary including packet
headers, release of queued allocations on disconnect, and the actual accept
path with real sockets and an injected foreign peer UID. Credential injection
covers the production UID check without requiring another account or privilege;
it does not replace the kernel's Unix-socket credential implementation.

Compile the sanitizer checks separately from running them. In the completion
campaign, prefix every compilation with its build gate:

```sh
tests/sol-ptybroker-build-checks.sh /tmp/ptybroker-checks
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 /tmp/ptybroker-checks/native-sanitize
TMPDIR=/tmp python3 tests/sol-ptybroker-streams.py --bash out/bash-sol-ptybroker \
  --loadable /tmp/ptybroker-checks/ptybroker-ubsan.so --output /tmp/streams-ubsan.json
```

The native harness uses ASan and UBSan. The shared loadable instruments the
wrapper and both production helpers with UBSan and aborts on undefined
behavior. Existing `tests/ptybroker.py`, `tests/ptybroker-io.py`,
`tests/screen-broker.py`, and `tests/pty-primitives.py` remain required companion
checks; these new workloads do not supersede their lifecycle, ownership,
geometry, malformed-packet, signal, output-backpressure, or descendant tests.

For a targeted compiled build, select `ptybroker,screen,pty,bashpoll` explicitly.
`screen` requires `ptybroker`; helper selection also pulls `_ptybroker`,
`_libssh`, `_mbedtls`, and `_jsmn` and links `-ldl`, `-lz`, and `-lpthread`.

The task-owned benchmark is `bench/sol-ptybroker.py`. Run it through the campaign
bench gate, which pins it and its children to one recorded CPU. It performs
one warm-up and at least seven measured passes per case, starting a fresh
private service each pass with identical content and options. Reports retain
every sample, work and delivered byte counts, fixture/source/binary SHA-256,
versions, CPU affinity, byte-validation status, latency samples, and broker
RSS/high-water marks. Timings include harness and Bash dispatch overhead.
Per-window request dispatch and active-reader progress waits are timed.
Creation, history capture, comparison, reconnection checks, and cleanup are
outside stream timing. Completion polling has 1 ms granularity, and stream times include subscriber teardown. Round-trip latency includes the driver pipes and shell
dispatch as well as the PTY relay. These are API measurements with no external
reference or ratio.

Metadata output now uses Bash's write-error check: `status`, `list`, and
`create` return failure if their status/list output cannot be written. The
check flushes output before returning and clears the stream error so later
calls in the same shell can succeed. A `create` output failure can occur after
the service was created; callers must inspect/terminate that session rather
than blindly retry creation. This does not change the native broker protocol
or packet ABI. Integration must revalidate `screen`, which depends on the
broker and shares its helper implementation.

Use a short `TMPDIR` such as `/tmp` for these tests. The campaign's longer
per-task temporary path can exceed the Unix socket's 107-byte pathname limit;
that is an invalid test fixture root, not a larger supported socket address.
The first unpaced stream trial also confirmed that a finite output queue can
disconnect active Bash consumers if generation outruns them. The bounded
burst and saturation-drain workloads specify production rates so that they
verify all accepted bytes; the existing unpaced overload test retains its
slow-disconnect and history assertions.

An unconstrained binary-relay warm-up also hit the subscriber queue limit on
the pinned CPU and was rejected before any valid timing. The measured relay
uses a 16 KiB acknowledgement window: each chunk must be received in full
before the next is sent. Its timing includes attachment, shell startup and
teardown in addition to dispatch and verified relay delivery. Producer rate,
consumer scheduling, and the finite queue policy matter; these measurements
are not an unlimited-rate delivery guarantee or a maximum PTY bandwidth claim.

Historical measurements below precede the active-reader window correction.
They measure the original sleep-paced streams and must not be labeled as
measurements of the current windowed harness. No new timings are claimed.
Re-run the benchmark on the integrated binary before publishing new figures.

The original UBSan burst test could evict an active observer even under the
serialized gate: a producer sleep does not guarantee that every consumer has
run. The corrected fixture limits each request to 64 KiB and waits until all
active observers have written that window. It keeps the exact full-payload,
contiguous-offset, slow-observer disconnect, history, reconnect and cleanup
assertions. The deliberately nonreading observer never participates in the
progress barrier, so overload handling is still exercised. This is a bounded
subscriber test, not a guarantee of unbounded-rate delivery.

Validated historical measurements on 2026-10-20 UTC used an Intel Core i7-9850H, Linux
6.12.111+deb13-amd64, GCC 14.2, Python 3.13.5, and Bash 5.3.15, pinned to CPU 11. Each row has one separate
warm-up followed by seven verified samples on the same binary. These rates
count unique PTY output bytes; the burst delivers three copies and sustained
output delivers two. The generation delays are intentional workload limits.

| Workload | Median time (min–max) | Median throughput | Maximum broker HWM |
| --- | --- | --- | --- |
| binary-relay | 66.18 ms (60.65–83.07) | 30.23 MiB/s | 5.94 MiB |
| burst-observers | 244.06 ms (221.67–288.62) | 16.39 MiB/s | 5.21 MiB |
| sustained | 1151.52 ms (1127.07–1171.45) | 6.95 MiB/s | 4.90 MiB |

The 256-byte round trips have a median latency of
211.6 microseconds and p95 of
339.3 microseconds across 448 verified operations
(seven independent 64-operation batches). Their largest broker HWM was
3.98 MiB. No external ratio or before/after speedup is claimed.

The compiled binary SHA-256 is
`3f9ca1280b10288c7e3244129625904ad41f44baa2354f3ee5c9459117f2f362`.
Raw reports, sample distributions, failed trials and exact validation commands
remain in the task evidence directory rather than the historical datasets.
Final compiled checks passed all six task cases, 20 broker lifecycle cases,
two I/O fixtures, 15 screen checks and 12 PTY primitive checks. Native ASan/UBSan
queue/authentication checks and the shared UBSan broker checks also passed.
Every workload's identity-aware cleanup succeeded; a final audit found no
owned broker services or fixture children.
