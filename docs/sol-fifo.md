# FIFO API and validation

`fifo` is a shell builtin with one process-local ring of **64 C `int` events**.
The ring uses a static array. The command opens no descriptors and needs no
terminal, external program, or companion loadable. It is an in-memory queue; `mkfifo(1)` is a
different operation. `--include fifo` selects it; the build system also stages
its default `_jsmn` helper without changes to that helper.

| Request | Success behavior |
| --- | --- |
| `fifo push INT [INT...]` | Append the entire argument sequence at the tail. |
| `fifo unget INT [INT...]` | Prepend the entire sequence in argument order. `unget 1 2` makes the next two pulls return 1, then 2. |
| `fifo pull` | Print and consume the head event. |
| `fifo peek` | Print the next event at an independent cursor and advance that cursor, without consuming. |
| `fifo clear` | Empty the queue and reset its indices and cursor. Safe when already empty. |
| `fifo depth` | Print the queued count, without moving the peek cursor. |
| `fifo -h` or `fifo --help` | Print API help, without changing state. |

`INT` is `[+-]?[0-9]+`, interpreted as decimal even with leading zeros, within
`INT_MIN..INT_MAX` (−2147483648..2147483647 on the tested build). Whitespace,
hex, trailing text, a bare sign, and overflow are rejected. The full batch must
fit the remaining capacity. Invalid syntax, missing/extra arguments, unknown
verbs and capacity errors return **2**, print no event, and preserve **both**
the entire queue and the peek cursor. No-argument verbs and help reject extra
arguments. Successful `push`, `unget`, `pull` and `clear` reset peek to the
current head. Empty pull and empty/exhausted peek return **1** without output
or state change; repeated exhausted peeks remain exhausted. Success returns 0.

Output is one decimal number and newline. `pull` and `peek` flush before
committing their state changes. A detected output error returns 1 and preserves
the queue/cursor; partial bytes may already have reached the destination.
`depth` and help also detect write errors. Later calls can use stdout again
after a failing redirection. Bash retains its normal signal handling for a
closed pipe.

State persists across calls and functions in the same shell. A subshell,
pipeline child, or command substitution receives a private inherited copy;
its mutations do not reach the parent. An independently started shell begins
empty. Read results using a redirection in the current shell if consumption
must persist: `fifo pull > private-file; read -r event < private-file`.
`event=$(fifo pull)` consumes only the substitution's copy.

The implementation now rejects leading whitespace previously accepted by
`strtol`, rejects extra help arguments, and detects output failures before
consuming an event or advancing peek. These are deliberate contract fixes.

Run the focused tests with `python3 tests/sol-fifo-check.py out/bash-sol-fifo`.
They retain the existing terminal-smoke FIFO sequence and add an independent
Python list/cursor oracle, all 64 ring head offsets, full and empty states,
overflow and invalid multi-value batches, all cursor reset paths, 4,000 seeded
mixed operations, persistent shell state, subshell isolation, private file
output, `/dev/full`, closed stdout and recovery. The task build helper produces
an ASan/UBSan module from the same production source; setting
`FIFO_TEST_LOADABLE` and `FIFO_TEST_ASAN_LIB` runs these same assertions against
that module. The test itself never compiles.

The native and ASan/UBSan runs passed **15,150 deterministic model operations**
and **4,060 seeded model operations**, plus the shell, output and help checks.
A fresh shell was checked while its parent's queue remained populated.
The historical module fails the new contract oracle, as expected. A separate
reproduction confirmed that it accepted `' 1'` and that `pull > /dev/full`
returned 0 while discarding the head event. The corrected builtin returns 1
and retains that event and its current peek position.

## Measurement method

`bench/sol-fifo.py` measures this API alone. There is no equivalent external
command reference, external ratio, or claimed before/after speedup. Every batch
handles **32 events** using one 32-argument push, 32 peeks and 32 pulls: **65 API
calls**, or 2.03125 calls per event. One event means one enqueued/dequeued entry
with one additional peek. A sample runs **128 batches / 4,096 events**.
The earlier review contained no FIFO measurement; these cases establish an API
baseline rather than supporting a speculative performance change.

| Case | Batch occupancy (start → after push → end) | Setup |
| --- | --- | --- |
| empty | 0 → 32 → 0 | Cleared ring; appends aligned to offsets 0 and 32. |
| half-full | 32 → 64 → 32 | Preload −32..−1; drain the remaining 32 events after the timed workload. |
| wraparound | 0 → 32 → 0 | Push/pull 60 setup events to place an empty ring at offset 60; subsequent appends alternate offsets 60 and 28, crossing the ring end in 64 of 128 batches. |

A fresh shell and `fifo clear` reset every pass. A Python list oracle constructs
all expected numeric output independently, including depth and final drain.
Every FIFO call checks its exit status. Every warm-up and timed sample must
match the expected bytes, exit 0, and emit no stderr; a failed case receives no
aggregate timing. There is one warm-up and nine samples per case with reversed
case order on alternate rounds. The process is pinned to one allowed CPU, and
children inherit that affinity.

Reported latency is amortized process wall time divided by 4,096 events. It
includes shell startup, fixture setup/drain, shell loop/control overhead,
formatting, flushing and output capture. It is not isolated C ring-operation
latency. Setup adds 60 push/pull events to wraparound and a 32-event preload
and drain to half-full; those costs remain in the wall time without subtraction.
The raw report records all sample times, statuses, distributions, CPU affinity,
versions, source/binary/fixture hashes, exact fixtures and build manifest.

Builds (including sanitizer compilation) must use the campaign build gate.
Run the benchmark separately through the campaign bench gate:

```sh
python3 "$GATE" build -- bash tests/sol-fifo-build.sh "$EVIDENCE"
python3 tests/sol-fifo-check.py out/bash-sol-fifo
python3 "$GATE" bench -- python3 bench/sol-fifo.py \
  --binary out/bash-sol-fifo --runs 9 --batches 128 \
  --output "$EVIDENCE/benchmark.json"
```

The software scope is the process-local FIFO API. Terminal decoders and live UI
interactions are separate APIs and receive no coverage claim from this work.

## Recorded result

The run on 2026-10-20 UTC used CPU 11 of an Intel Core i7-9850H, Linux
6.12.111, glibc 2.41, GCC 14.2.0 and Bash 5.3.15(1). All three warm-ups
and all 27 measured samples passed exact output and status validation.
Each row contains nine samples of 128 batches, with 32 events per batch.

| Case | Median ms/batch | Median µs/event | Min–max µs/event |
| --- | ---: | ---: | ---: |
| empty | 0.515699 | 16.116 | 13.157–25.697 |
| half-full | 0.534999 | 16.719 | 14.371–21.296 |
| wraparound | 0.490047 | 15.314 | 13.163–18.402 |

These are amortized API costs including the overhead described above. All
samples, including the full observed range, are retained in the raw report
`$EVIDENCE/benchmark.json`; scripts and independent expected bytes are in
`$EVIDENCE/benchmark-fixtures/`. No external ratio applies.

Source SHA-256: `87e8dc4011956e76eae01040607049939a1b9a4a8d2d3e139131ff29762cd41a`.

Binary SHA-256: `2fb06bd8e688b1805f8494a8260336f948c82c1c6cf9167ef5091ff2d23a0dff`.
