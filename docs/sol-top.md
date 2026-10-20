# top deterministic coverage and measurements

`top` is a native `/proc` process viewer. `--once`, `-b`, and `--batch` each
produce one snapshot using two observations 200 ms apart. `-n` controls
interactive redraws, not batch repetitions. CPU percentages are shares of total
machine time; they are not procps's per-CPU percentages. This scope does not
claim full procps option or screen parity.

The command now rejects malformed decimal counts, row caps, delays, and prompt
values. Counts and row caps accept zero as unlimited/automatic. Delays accept
1 through 3599 integer seconds, consistently in options and prompts. Negative
PID/group targets and malformed mutation requests are rejected. Nice deltas
accept -40 through 40. Unexpected operands fail with usage status.

CPU totals exclude guest and guest_nice, already accounted for in user/nice.
Process identity includes starttime, so PID reuse starts a fresh observation.
Missing, truncated, and vanished stat records are excluded. Nonadvancing system
counters and decreasing process counters produce zero percentages. CPU, memory,
and time ties sort by descending PID; PID sorting is ascending. Batch write
failures return failure, and previous observations are freed after each call.
Interactive redraws apply pending terminal size changes before choosing rows,
empty process lists reset scrolling, and normal exits restore the calling
shell's signal dispositions as well as the terminal.

`tests/sol-top-check.py` runs the production command with a test-only preload
shim. All `/proc` file opens and directory scans are redirected into private
fixtures. Kill and priority operations are intercepted, recorded, and never
sent to a process. The fixtures independently specify stat field positions,
CPU increments, guest counters, memory totals, process identities and expected
formatted rows. Tests compare full batch output and decoded terminal cells,
not live host counters or a second invocation's output.

Coverage includes all sort modes and ties; command-line and fallback command
names; creation, exit, reuse, empty lists and repopulation; malformed input;
empty PATH; repeated invocations and FD counts; output failures and recovery;
private PTY arrows/pages/home/end, space, sort cycling, delay prompts, mutation
request construction, resize, redraw count, timeout, q/Q/ESC/Ctrl-C, TERM/HUP,
terminal attributes, cursor and alternate screen restoration, and shell traps.
The sanitizer build instruments top and the actual shared screen/key helpers.

Validation on 2026-10-20 passed all 116 checks in both the native and
ASan/UBSan runs. A separately compiled copy of the original source reproduced
malformed-option acceptance, truncated-record inclusion, guest-time
double-counting, and a false 45.5% CPU charge to a reused PID.

Build and run, using the campaign build gate for every compilation:

```sh
# Set BASHOS_TASK_DIR to a private evidence directory first.
python3 "$GATE" build -- bash tests/sol-top-build-fixtures.sh
python3 tests/sol-top-check.py out/bash-sol-top "$BASHOS_TASK_DIR/proc-shim.so"
python3 tests/sol-top-check.py out/bash-sol-top "$BASHOS_TASK_DIR/proc-shim.so" \
  --loader "$BASHOS_TASK_DIR/sanitize/load.sh" \
  --asan "$(cat "$BASHOS_TASK_DIR/sanitize/asan-path")"
python3 "$GATE" bench -- python3 bench/sol-top.py \
  --binary out/bash-sol-top --shim "$BASHOS_TASK_DIR/proc-shim.so" \
  --runs 7 --output "$BASHOS_TASK_DIR/benchmark.json"
```

The build selection is `--include top --name sol-top`. Helper resolution adds
`_bl_screen` and its `_bl_key` dependency; no companion command is necessary.
No shared helper or catalog file is changed. Integration should register the
new command test separately and revalidate it when the common helpers change.

The benchmark uses fixed 64-, 1024-, and 4096-process snapshots and a private
24-by-100 terminal showing 20 of 1024 processes. Every pass has an independent
output oracle. One warm-up precedes seven samples, pinned to one recorded CPU.
Batch timings include shell startup and the intentional 200 ms sampling delay.
Refresh timings include sampling, formatting, key dispatch, terminal output
and parent-side cell decoding. Terminal byte counts exclude startup and exit
sequences. Reports record source/binary/shim hashes, fixture hashes, versions,
affinity, individual samples and validation results. These are fixture-backed
self timings with no external ratio or speedup claim.

On 2026-10-20, all four measured cases passed every warm-up and measured
pass on CPU 11 of an Intel Core i7-9850H, Linux 6.12.111, glibc 2.41,
Bash 5.3.15 and GCC 14.2 (`-O2`). Seven samples followed one warm-up:

| Fixed workload | Median ms | Min–max ms | Terminal bytes per refresh |
|---|---:|---:|---:|
| Batch, 64 processes, all rows | 214.020 | 210.015–219.358 | — |
| Batch, 1024 processes, all rows | 317.525 | 296.668–332.199 | — |
| Batch, 4096 processes, all rows | 565.472 | 551.716–589.383 | — |
| Refresh, 1024 processes, 20 visible rows | 21.992 | 20.436–24.574 | 126 |

The initial terminal frame emitted 1480 bytes. The measured refreshes alternate
between the two fixed snapshots; the backward-counter transition deliberately
exercises the zero-delta path. All seven emitted 126 bytes. This establishes a
measured baseline; it is not evidence of an optimization or a comparison with
another top implementation. Raw data and receipts are `benchmark-1.json`,
`benchmark-1.log`, and `result.json` in the task evidence directory. The measured
binary SHA-256 is
`f44b308eaab99be05d6ae7eaa292dea1f076d4d4caff4a88ab1da56b90cbe327`.

The scope is Linux software paths with injected proc records and private PTYs.
It does not qualify every terminal emulator, allocation failure, all malformed
kernel data, real signal/renice effects, or the helper's handling of terminal
write failures. Batch output errors are covered. The existing 8192-process
sampling cap remains. No hardware is required for this software-path scope.
