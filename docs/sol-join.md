# Join: byte fields, reusable groups and focused qualification

Each invocation owns its stdin stdio buffer and closes it on ordinary success/error paths. `tests/review-join-streams.py` checks that output failure cannot carry buffered bytes into a later redirected invocation, for either input operand. It also checks descriptor cleanup and closed-output safety.

The measurements below predate this review correction. They describe the original
worker implementation; they are not measurements of the corrected code. No new
performance claim is made for this correction.

`join` supports sorted C-locale inputs, duplicate-key Cartesian groups,
`-1`/`-2`/`-j`, single-byte `-t`, `-i`, `-a`/`-v`, `-o`/`-e`, `-o auto`,
headers and order checking. This qualification covers that implemented surface;
it does not establish complete GNU command-line or locale conformance.

The implementation represents fields as byte slices into the record's input
buffer. Embedded NULs, trailing carriage returns and high-byte separators remain
ordinary bytes. Record and output-field arrays grow with the input rather than
silently stopping at 64 fields. Invalid numeric arguments and input read errors
return failure. Each invocation resets standard-stream error flags.

Matched rows transfer their buffers and field slices into reusable group slots.
The next read reuses the previous slot's storage. This removes the second
split and both record copies formerly performed by group insertion. Order
checking keeps its own previous key so moving records preserves its semantics.
Both groups remain in memory for Cartesian output: memory grows with the
largest duplicate groups, and large groups retain their buffers until the
invocation ends. There is no spill-to-disk path.

`tests/join-check.sh BINARY` retains the original assertions, including fatal
write failures with a FIFO producer held open. It invokes
`tests/sol-join-check.py` for byte comparisons against GNU join, independent
Cartesian and long-line oracles, seeded changing groups, missing/empty fields,
binary input, many fields, output selection, repeated input streams, error
recovery and descriptor counts. `tests/join-reuse.py` remains an additional
changing-group comparison. Every shell invocation uses an empty `PATH`.

`tests/sol-join-build-tools.sh sanitize OUTPUT` compiles a standalone
ASan/UBSan entry into the production translation unit, mocking only Bash's word
list and diagnostic interfaces. Run the same byte cases with
`SOL_JOIN_NATIVE=1 python3 tests/sol-join-check.py OUTPUT`. Its repetition check
calls the production builtin 80 times; shell descriptor/redirection checks are
covered by the normal executable tests.

`bench/sol-join.py --binary BINARY --rusage-launcher LAUNCHER --runs 7 --output REPORT` measures fixed
historical, high-duplicate, large-group and large-field unique-key workloads.
Builds and measurements must use the campaign's respective resource gates.
The historical fixture is the unchanged shared harness's 10,000 left and
5,000 right rows, with 18 invocations per batch. The adapter records fixture
and binary/source hashes, exact work, affinity, versions, sample distributions
and peak RSS. A small native launcher forks after exec, then uses `wait4`
to measure the shell and its waited children. This avoids inheriting the Python
fixture generator's pre-exec peak. Build it with the `rusage` mode of
`tests/sol-join-build-tools.sh`. Every invocation, including warmup and every timed
pass, has its own output file and must match an independently generated expected
byte sequence with success status. Both implementations run from the same Bash
executable; GNU uses an absolute command path. Files are overwritten per pass,
inputs are unchanged and warm page cache is used. Output-file writes and shell
startup are included in the timings.

An optional instrumented module, built with the `profile` mode and supplied as
`--profile-module MODULE`, records production `bj_split` and `bj_group_add`
call counts and inclusive instrumented durations. These are separate profile
passes, not throughput timings. Split time is nested inside group-insertion
time in the old implementation, so those durations must not be added.

The standalone ASan/UBSan run passes 215 checks with leak detection enabled.
This exercises the production parser, readers, group ownership, output and
cleanup code; it does not instrument Bash itself. The native executable additionally passes all 31 shell assertions and 215
byte/state checks; the existing reuse suite passes 18 checks. The shell checks
cover both stdin positions, redirection after EOF, write-failure recovery,
failed opens/reads and stable descriptor counts across 80 iterations. All four
held-producer tests stop promptly after output failure.


## Measured results, 2026-10-19

Intel Core i7-9850H, CPU affinity `{11}`, Linux 6.12.111, glibc 2.41,
GCC 14.2.0, Bash 5.3.15 and GNU coreutils join 9.7. Both focused binaries use
the same default `-O2` hardened build options with symbols retained. No companion
command is required (`--include join`); the build resolves its default `_jsmn`
helper without shared-helper edits.

The unchanged `bench/loadables.py --only join --passes 18 --runs 7` case measured
32.248 ms builtin / 46.502 ms GNU before, and 35.056 / 55.709 ms after.
The historical 1.53× external-time slowdown therefore did not reproduce on the
starting build. The new builtin is 0.63× external time in this run. These are
current measurements, not a paired speedup against the old historical snapshot.
Both per-case JSON statuses are `ok`; BusyBox was unavailable.

The stricter adapter includes output-file writes and a native memory launcher,
so its wall times are separate from the shared harness. Each cell below is the
median of seven batch samples after a warmup. The GNU column uses the new
binary as its shell. Every timed invocation and every profile pass matched an
independently generated byte oracle; input/output hashes match between builds.

| Workload | Invocations/batch | Before ms | New ms | GNU ms |
|---|---:|---:|---:|---:|
| Historical: 10,000 left + 5,000 right rows | 18 | 38.773 | 35.440 | 55.109 |
| 120 keys, 40×35 rows per key; 168,000 output rows | 3 | 37.554 | 40.350 | 50.387 |
| One key, 4,000 left rows with 8,198-byte fields × one right row | 2 | 203.788 | 143.527 | 445.492 |
| 2,000 unique keys with 8,192-byte left fields | 3 | 121.585 | 82.479 | 302.492 |

Large-group batches improved by 1.42× and large-unique batches by 1.47×.
Their seven-sample ranges were 195.80–253.64 → 136.60–155.75 ms and
106.45–140.19 → 79.43–96.97 ms respectively. The short-field Cartesian workload
shows no speedup; its ranges overlap (36.25–39.26 → 36.79–42.19 ms).
The machine was shared, and samples remain available for interpreting noise.

Peak RSS is the maximum across the seven batches, in KiB, including the Bash
shell and its waited children; it excludes the Python fixture generator and
file cache. Baseline shell memory dominates the small cases.

| Workload | Before KiB | New KiB | GNU KiB |
|---|---:|---:|---:|
| Historical | 3,312 | 3,344 | 3,332 |
| High duplicate count | 3,352 | 3,280 | 3,284 |
| Large duplicate group | 69,812 | 51,748 | 45,844 |
| Large unique fields | 3,416 | 3,304 | 3,272 |

Large-group peak RSS fell 25.9%. Reused group slots still retain their allocated
capacity until the invocation finishes; the builtin does not promise GNU's
memory footprint or spill groups to disk.

Instrumented production calls explain the tokenization change. Split calls per
invocation fell from 25,000 to 15,000 for the historical fixture, 18,000 to 9,000
for high duplicates, 8,002 to 4,001 for the large group and 8,000 to 4,000 for
large unique fields. Group-insertion counts stayed unchanged. In the large-group
profile, median inclusive splitter time fell from 60.53 to 21.99 ms, and group
insertion from 43.06 to 0.277 ms. The old insertion time contains nested splitter
time. These instrumented durations have instrumentation overhead; the separate
wall samples above establish the throughput result.

Raw evidence is retained as `before-v3.json`, `after-v3.json` and their
`*-historical.json` sidecars in the task evidence directory, with full sample
and RSS distributions, versions, fixture hashes and binary/source hashes.
The final source SHA-256 is
`7c2bb052f47349c9ec56251df66b0e5c3842b1a93b564a401a0cb675fc1c84be`;
the binary SHA-256 is
`b589d7fa1d940f2475a28dc4715689119926e847c03af55e73436aa1bd074461`.
Earlier reports are preserved separately: the first adapter attempt lacked
`/usr/bin/time`, and `before-v2.json` has invalid inherited-parent RSS values.
Those memory values are excluded from this report. The native fork/`wait4`
launcher fixes that accounting error.
