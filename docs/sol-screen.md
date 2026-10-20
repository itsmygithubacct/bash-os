# Live screen relay qualification

These checks extend [the live-pane suite](../tests/screen-broker.py) and
[the broker contract](ptybroker.md). They execute production `screen` and
`ptybroker` against private Linux PTYs, with an empty executable `PATH` and
explicit child executables. Select both commands:

```sh
./build.sh --include screen,ptybroker --name sol-screen
TMPDIR=/tmp python3 tests/screen-broker.py --bash out/bash-sol-screen
TMPDIR=/tmp python3 tests/sol-screen-streams.py --bash out/bash-sol-screen \
  --output /tmp/screen-streams.json
```

In the completion campaign, run compilation through the build gate and
measurements through the bench gate. These Python tests do not compile.
Use a short temporary root to respect the Unix socket pathname limit.

The original suite remains required. It checks split, focus, window switching,
resize and swap against child-observed geometry; binary capture; invalid
mutations; output failures; controller exclusivity; observer input suppression;
disconnect; child exit; resistant descendants; concurrent creators; and cleanup.
The new suite adds the following live workloads:

| Case | Fixed work and independent oracle |
| --- | --- |
| Sustained relay | 8 MiB of deterministic binary output from a real child, through `screen attach` to a controller and observer. Both streams must exactly match the arithmetic byte pattern. |
| Controlled slow reader | The observer reads at most 4 KiB then sleeps 1 ms. Each 64 KiB production window waits for both active readers. A third, nonreading observer is excluded from that barrier and must be evicted with a failing screen exit. |
| Concurrent mutations | During the stream, another thread performs 24 resize/swap pairs on live panes. All 48 mutations must succeed, and the focused pane retains its byte identity. |
| Binary relay | 2 MiB + 719 bytes pass through controller input and raw child echo in 16 KiB windows. The driver quotes literal Ctrl-A bytes and compares every returned byte, including the final partial window. |
| Binary round trip | 64 serial requests of 256 bytes, including NUL, high bits and the quoted screen prefix, sent through the controller and echoed by a raw child. Each reply is compared with independently generated input. |
| Child exit | Final binary output must arrive before the attachment exits; broker status must retain child exit 17. |
| Literal argv | Empty, spaced, multiline, wildcard, quote and shell-looking arguments are compared with the child's JSON argv in run, window-create and split paths. |
| Repeated calls | 32 attach/state/invalid-resize cycles in one shell with no FD count growth; a private frontend PTY must recover its exact termios settings after detach. |

The stream checks require exactly 8 MiB of broker offset advancement and the
exact final 1 MiB history suffix. Each window samples the history extent and
records the first output-byte boundary at which stalled-observer eviction is
visible. That boundary includes kernel buffering and is not a direct measure
of subscriber heap occupancy. They sample broker RSS/HWM and impose a
32 MiB regression ceiling. This ceiling is deliberately generous and excludes
the frontend, fixture, and kernel socket buffers. The exact 1 MiB input and
256 KiB subscriber queue boundaries are separately exercised by the existing
production-code harness `tests/sol-ptybroker-native.c`, including atomic input
rejection and release of output allocations on disconnect. No broker queue
instrumentation or protocol change is needed.

Controller input EOF and observer output loss are followed by subscription
count checks; neither may terminate the pane. Every case calls production
session cleanup and checks process identities and state removal before the
test harness's emergency cleanup can run.

The pending-prefix regression sends a lone Ctrl-A before closing the
controller's input pipe. A drained pipe can report `POLLHUP` without
`POLLIN`; screen previously dropped that byte even though its ordinary
`read()` EOF branch forwarded it. The hangup branch now forwards the literal
pending prefix before disconnecting. The test checks the child's received
byte independently of the departing frontend's output. Observer input remains
suppressed. This fix is screen-owned and does not alter the broker API.

`tests/sol-screen-build-checks.sh OUTPUT` compiles UBSan modules for screen
and its broker companion and the existing ASan/UBSan native queue harness.
Run that script through the build gate, then run:

```sh
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 OUTPUT/native-sanitize
TMPDIR=/tmp python3 tests/screen-broker.py --bash out/bash-sol-screen \
  --load-dir OUTPUT
TMPDIR=/tmp python3 tests/sol-screen-streams.py --bash out/bash-sol-screen \
  --load-dir OUTPUT --output /tmp/screen-streams-ubsan.json
```

The screen module uses the compiled executable's exported SSH symbols; the
local screen and broker code is instrumented. This does not instrument or
qualify remote SSH behavior.

Measure with:

```sh
TMPDIR=/tmp python3 bench/sol-screen.py --bash out/bash-sol-screen \
  --runs 7 --output /tmp/screen-live.json
```

The driver requires a single CPU affinity. It runs a validated warm-up and
seven validated samples of each timed case with fresh private services.
Reports include every duration and latency sample, payload/fixture/source/
binary hashes, versions, CPU affinity, reset rules, work and byte counts,
and memory observations. Timings are API measurements with no external
ratio. Sustained timing includes stream requests, the slow reader, progress
barriers, all concurrent mutations and per-window status/memory sampling. Setup, history
validation and cleanup are outside that interval.
Round-trip latency includes Python pipes, screen prefix decoding, broker
requests, PTY processing and child echo. These figures do not claim maximum
unpaced PTY bandwidth. The separate historical `screen remote-frame decode`
case measures frame decoding, not live panes.
Throughput counts unique payload bytes: the sustained case delivers two
complete copies, while the binary relay sends and receives the same payload.

Qualification is limited to local raw-byte relay on Linux with `/proc`,
Unix `SOCK_SEQPACKET`, subreapers and pidfds. The fixture uses a private PTY
to check frontend raw-mode restoration; it does not qualify a physical
terminal, GPU compositor, Kitty/Sixel rendering, SSH/network transport or a
specific end-user device. Screen follows the focused pane and does not
composite all panes into a terminal grid. Detached terminal queries are not
answered, history is not a terminal checkpoint, and attachment does not
replay history. Focus changes intentionally start a new live subscription;
lossless delivery across an unfocused interval is not promised. A finite
subscriber queue can disconnect a reader when generation outruns it.
Device/frontend qualification must preserve those limitations.

Measurements on 2026-10-20 used an Intel Core i7-9850H, Linux
6.12.111+deb13-amd64, GCC 14.2, Python 3.13.5 and Bash 5.3.15, pinned
to CPU 11 through the campaign gate. Each row has a separate validated
warm-up and seven validated samples:

| Workload | Median elapsed (min–max) | Median unique-payload throughput |
| --- | --- | --- |
| 8 MiB sustained stream, slow observer, 48 mutations | 3.125 s (3.075–3.253 s) | 2.56 MiB/s |
| 2 MiB + 719-byte binary echo | 127.67 ms (124.42–142.73 ms) | 15.67 MiB/s |

Across 448 verified 256-byte round trips, median latency was 139.0 µs,
p95 was 226.5 µs, and the range was 96.7–364.9 µs. Every sustained
sample delivered exactly 8 MiB to each active reader, observed stalled
subscriber eviction by the 448 KiB output checkpoint, and retained exactly
the last 1 MiB of history. The maximum sampled broker HWM was 5.18 MiB.
The exact native queue-boundary checks also passed under ASan/UBSan.

The unchanged historical frame-decode harness passed 35 output validations
and seven samples on each binary: baseline median 67.783 ms per 35-call
batch and corrected-binary median 61.460 ms. It uses a self-consistency
oracle and measures a different path from the independently checked live
workloads. These figures establish reproducibility; no frame-decoder
optimization or causal speedup is claimed.

The measured final binary SHA-256 is
`fef2b3695b6099633908496d0ef0a0042b3a6aa829ed5c177962e3c9e143584f`.
Raw reports retain all samples, warm-ups, fixture and source hashes,
validation statuses and exact commands in the task evidence directory.
The baseline EOF-prefix failure is retained there alongside the passing
corrected test. Both compiled and UBSan-module runs passed the five new
cases and the original 15 screen checks. The compiled broker lifecycle
suite passed 20 cases, and its two I/O fixtures also passed.
