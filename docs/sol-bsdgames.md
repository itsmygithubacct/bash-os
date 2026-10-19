# bsdgames filters and deterministic input contracts

This report covers the native `bsdgames rot13` and explicit-shift `caesar`
filters, with representative contracts for `number`, `morse`, `primes`, the
bounded Adventure adapter and seeded Wumpus. It does not establish upstream
BSD-games parity for every adapter or replace their documented scope limits.
The available ROT13 reference is GNU `tr A-Za-z N-ZA-Mn-za-m` under `LC_ALL=C`.
It maps ASCII letters and preserves all other bytes, including NUL and bytes
128–255. Arguments are joined with spaces and receive a trailing newline;
stdin is a byte filter and preserves the input's final-newline state.

`tests/sol-bsdgames-contracts.py BINARY` exercises pipes and regular files,
empty input, every byte, mixed binary records, multi-MiB lines, dense newlines,
and 64 KiB boundaries. Repeated calls in one shell distinguish different
inputs by their bytes. A `number` call followed by ROT13 tests stdio read-ahead
on the same stream. Early quit followed by different files, the same reopened
inode, a pipe and here-strings checks for stale buffered commands. Empty `PATH`, output ordering, read and write errors,
recovery after errors, closed descriptors, ignored-SIGPIPE handling, descriptor
counts, and line delivery before EOF on a pipe and a private PTY are covered.
Game checks include known prime values, Morse output, Adventure inventory and
movement, and seeded Wumpus invalid-command and quit handling. Their state root
is private and the tested games must leave it unused.

Build only the command:

```sh
./build.sh --include bsdgames --name sol-bsdgames --no-strip
python3 tests/large-smoke.py out/bash-sol-bsdgames bsdgames
python3 tests/sol-bsdgames-contracts.py out/bash-sol-bsdgames
```

`config/helpers.json` declares no required companion for `bsdgames`; selection
uses the shell base and the default `_jsmn` header helper. No common helper or
catalog file is modified by this task. Campaign builds and measurements must
be wrapped by the campaign's `gated.py build --` and `gated.py bench --`
respectively. The commands above are the wrapped payloads, not instructions to
bypass that gate.

For sanitizer checks, set `BASHOS_TASK_DIR` to a private artifact directory,
build with `bash tests/sol-bsdgames-build.sh` through the build gate, then run
the focused Python test with `BSDGAMES_LOAD_ENV=$BASHOS_TASK_DIR/load-sanitize.sh` and
`BSDGAMES_ASAN_LIB` set to the path in `asan-library.txt`. The test injects
ASan/UBSan only into child processes, disables leak checking of the host shell,
and aborts on sanitizer errors.
The build script also creates the transform-only measurement executable;
compilation and measurement are separate gated operations.

## Measurement method

The historical case uses 1,680,000 bytes of `00000000 word\n`-shaped records,
120,000 records, three passes and seven samples. The shared `bench/loadables.py`
case is invoked unchanged to reproduce its calling pattern and validation.
The historical 100.655/8.014 ms result is context, not a paired baseline for
this host/build.

`bench/sol-bsdgames.py --before BEFORE --before-source BEFORE_SOURCE --after AFTER --output REPORT` measures
that exact fixture, binary inputs from zero through 8 MiB, an 8 MiB line and
1 MiB of dense newlines. Each implementation runs in a persistent shell loop,
with stdin reopened for each pass. There is one warm-up and at least seven
samples, with implementation order rotated and reversed. Every call's status
is checked and every timed batch's complete output is compared with an
independent ASCII translation oracle and GNU `tr`. Output is a private regular
file, truncated before each batch; validation occurs after timing. These file
sink results must be distinguished from the shared benchmark's `/dev/null`
sink. Every sample records the output digest and validated pass count.

The report gives outer process/driver wall time and Bash's internal batch time
separately, along with an empty-loop control. Bash's millisecond time reporting
limits resolution for tiny inputs. No subtraction is presented as a pure
transform estimate. `tests/sol-bsdgames-transform.c` includes the production
source and calls the actual translation function. It times only translation,
excluding allocation, input, map setup, output, launch and validation. Every
8 MiB pass is checked against an independently constructed alphabet-half
oracle, with one warm-up and seven samples of sixteen passes each. That is an
API microbenchmark, with no external-tool ratio.

## Correctness changes

The argument-text path now checks each output write and the final flush.
Previously `bsdgames rot13 hello > /dev/full` returned success. Both the
argument and stdin forms now return failure for this condition and can be
followed by a healthy call in the same shell.

The entrypoint also distinguishes input streams by their descriptor's device,
inode and type, clearing stale stdio read-ahead when the input changes. After
a game finishes with regular-file stdin, POSIX input `fflush` synchronizes the
file descriptor to the logical read position before Bash restores redirections.
This prevents an early `quit` followed by a new redirection from executing old
buffered commands, including when the same inode is reopened. Sequential games
on one pipe retain their unread bytes; sequential readers of one open regular
file see the correct remaining bytes. No descriptors are retained between calls.
The stream check uses Bash's existing portable `fpurge` API; no common helper
implementation changes are needed.

## Validation and current measurements

The final targeted binary passed 136 focused contract checks and the 12
unchanged `large-smoke.py` bsdgames checks. Both sets also passed with the
production implementation loaded under ASan and UBSan. The initial code failed
the new `/dev/full` argument-mode assertion and early-quit/reopened-input
assertions; the final code passes them. Those attempt-1 logs and binaries are
preserved unchanged.

The attempt-2 campaign bench gate admitted all measurements on 2026-10-19,
pinned to CPU 11: Intel Core i7-9850H, Linux 6.12.111, GCC 14.2.0, glibc 2.41,
Bash 5.3.15 and GNU coreutils 9.7. No rebuild was needed. The saved before
source equals `5a91c6e`; the final implementation is `fb32e7b`. All source,
binary, harness and reference SHA-256 values, exact arguments, environment,
fixture hashes and sample distributions are in
`measurement-manifest-attempt-2.json` and the separate raw reports. Source
hashes are `8eee85cb8cc939c52a6627ab42c25efd53856ccdbbfb533e5ea752d422456efb`
(before) and `684b45e351126b4242362086fd06bd850e7c1e4227e10cf8a4c640b5952addfc`
(final). Binary hashes are
`ff17d452d5d3f26b39b3f29363d7ee443dfb41f610f8db66d8b89589547a8c8d` and
`41ea24eddd12b8b712f25abc1fdd630dade0f35e16c7280e83d9694ee2259af3`.

The unchanged shared harness used three invocations over the same
1,680,000-byte fixture, output to `/dev/null`, repeated-batch byte validation
as warm-up, then seven timed batches with every command status checked.
All builtin, GNU and BusyBox case statuses were `ok`; no timing is taken from
a failed case. The fixture SHA-256 is
`27b777784c9b2451929fb1bcc63c125b2889c2cd41423422616b97d662bdded6`.

| saved build | builtin median ms [min–max] | GNU tr median ms [min–max] | builtin / GNU |
|---|---:|---:|---:|
| before | 5.767 [5.566–6.455] | 8.814 [8.221–9.032] | 0.654× |
| final | 5.729 [5.480–6.124] | 8.600 [7.871–8.898] | 0.666× |

The former **12.56× slowdown does not reproduce** on the current code.
Historical source `63cb23d` uses per-byte `getchar`/`putchar`, alphabet tests
and modulo arithmetic; the assigned baseline already uses a lookup table and
64 KiB regular-file blocks. These source changes are a plausible explanation
for the difference, but the historical executable was not remeasured here.
The historical 100.655/8.014 ms figures are not a paired baseline, and no
historical-host speedup or causal decomposition of that timing is claimed.
The fresh results support retaining the existing algorithm and buffering;
this task adds no speculative performance optimization.

The task-owned sweep uses the same persistent-shell repeated-redirection
pattern, with a regular-file sink. Each warm-up and timed batch validates
complete bytes against GNU `tr` and an independent ASCII oracle after stopping
the clock. All ten cases, all four implementations/controls and all seven
samples passed. Medians below are milliseconds per batch, including process
launch for the outer columns. The final inner column is Bash's timed loop;
its millisecond resolution limits tiny-input interpretation.

| fixture | passes | before outer | final outer | GNU outer | final inner | empty-loop outer |
|---|---:|---:|---:|---:|---:|---:|
| historical duplicates | 3 | 8.207 | 8.137 | 12.298 | 5 | 1.606 |
| empty | 10 | 2.680 | 2.725 | 9.774 | 0 | 2.656 |
| binary 1 B | 10 | 2.719 | 2.852 | 9.748 | 0 | 2.816 |
| binary 64 B | 10 | 2.724 | 2.794 | 10.398 | 0 | 2.599 |
| binary 4 KiB | 10 | 2.800 | 2.830 | 9.986 | 0 | 2.798 |
| binary 64 KiB | 10 | 3.509 | 3.481 | 10.595 | 1 | 2.705 |
| binary 1 MiB | 3 | 5.676 | 5.675 | 8.293 | 3 | 2.541 |
| binary 8 MiB | 3 | 31.527 | 34.648 | 39.063 | 32 | 3.161 |
| one 8 MiB line, no final newline | 3 | 33.607 | 34.491 | 41.698 | 31 | 1.871 |
| dense newlines, 1 MiB | 3 | 6.621 | 6.655 | 10.180 | 4 | 1.741 |

For binary 8 MiB, before/final outer ranges were 27.896–38.444 and
29.001–37.286 ms. The variation and overlapping distributions do not support
a speedup claim between these saved binaries. Empty-loop controls expose
launch/driver/loop overhead; none is subtracted to invent a pure-transform
estimate. File-sink timings are kept separate from the shared `/dev/null`
results.

## Byte-loop and output profile

The separately built harness calls the production `bsdg_caesar_transform`
function and checks every pass against the independent alphabet-half oracle.
One warm-up and seven samples each transform sixteen 8 MiB buffers (128 MiB
per sample). Sample totals were 73.935, 74.877, 76.125, 78.676, 78.708, 91.669
and 93.521 ms: median 78.676 ms, or 1.589 GiB/s. This measures the in-memory
lookup loop plus clock overhead, with allocation, map setup, input/output,
launch and verification excluded. Verification between passes also affects
cache state. It is an API measurement with no external-tool ratio.

`bench/sol-bsdgames-profile.py` traces the actual production filter for three
historical-fixture passes, validating all emitted bytes to a private regular
file. Both saved builds read and wrote exactly 5,040,000 bytes: 81 stdin reads
(75 × 65,536 bytes, three 41,600-byte tails and three EOF reads), and 293 stdout
writes. The write sizes were 74 × 61,440, 77 × 4,096, 135 × 14, three × 36,864,
three × 10 and one × 65,536 bytes. Thus output already uses bulk writes,
with some small tails from shared stdio buffering. Trace timings are not used
as throughput samples. Saved disassembly shows the table-load/store loop and
one `fwrite_unlocked` call per nonempty block, matching the production source.

Hardware `cycles,instructions,branches,branch-misses` and software
`task-clock,cpu-clock` counter attempts both exited 255 on both builds:
`perf_event_paranoid=3` denied performance monitoring. Their stderr and reports
are preserved as unavailable evidence, not successful profiles. No host policy
was changed. Byte-loop timing, assembly and syscall-volume evidence remain
available; instruction counts and sampled CPU attribution are unqualified.

Raw evidence is separate from historical datasets: `historical-before-attempt-2.json`,
`historical-final-attempt-2.json`, `sweep-attempt-2.json`, and
`profile-attempt-2/profile.json`, with exact commands in
`receipts-attempt-2.jsonl`. `audit-attempt-2.log` checks case/sample statuses,
work counts, independent fixture/output hashes, fixed affinity, source/binary
hashes, counter failures and every preserved attempt-1 artifact. The sweep
needed no execution-path repair; it now records explicit successful sample
statuses and refuses existing output reports or unpinned execution.

This completes the ASCII-filter performance and representative adapter-contract
scope. Full upstream BSD-games parity, actual interactive-game play coverage,
pipe/TTY throughput and hardware-counter qualification remain outside this
scope; pipe/TTY incremental correctness is covered by the focused tests.
