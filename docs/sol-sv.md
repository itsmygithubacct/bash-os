# sv lifecycle and logging completion

This work covers the native supervisor's lifecycle and log paths with private
service, runtime and log directories. No host service is started or signalled.
The focused build selects `sv` alone: the credential implementation is a header
included by `sv.c`; no companion loadable is required for these cases. Namespace,
privilege-drop, socket/path activation and notify protocol qualification remain
outside this logging/lifecycle test scope. There are no shared helper changes.

`tests/sol-sv-check.py BINARY` exercises binary and long records, unterminated
records, a nonseekable FIFO log, repeated invocations with an empty PATH,
stdout failure and recovery, FD balance, rotation at service-log open, exit and
signal policies, restart limits, finish arguments, oneshot idempotence, explicit
restart, disabled-service boot and reverse dependency shutdown/finish order. Capture producers write independent byte-count and
SHA-256 receipts after completing output. Tests also force failed log opens,
`/dev/full` write failures, a TERM handler writing beyond pipe capacity, and a
TERM-ignoring owned child. The harness adopts and reaps its supervisors and cleans
up only its own descendants.

Build `tests/sol-sv-build-fixtures.sh OUTPUT [ORIGINAL_SV_C]` through the build gate
to produce the short-write/EINTR shim and the ASan/UBSan runtime loadable. Set
`SV_TEST_WRITE_SHIM=OUTPUT/write-shim.so` for injection, or set
`BASH_ENV=OUTPUT/asan-env.sh`, preload the library named in
`OUTPUT/asan-library.txt`, and set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`
and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` for sanitizer checks.

The optional original-source argument also builds two small executables that
call the production timestamp framing function directly. Link-time section
collection discards unrelated loadable entrypoints. This measures framing and
copy/write costs separately from supervised-child scheduling; every output is
validated against the input after removing syntactically checked timestamp
prefixes. The copy control writes the identical input without timestamping.

`bench/sol-sv.py --binary BINARY --output REPORT --profile` runs through the bench
gate. It includes one warm-up and seven samples, records inherited CPU affinity,
source/binary/fixture hashes and versions, and checks every status and output.
The `sv-log` fixture and its 29 passes match the existing catalog case: 2,800,000
input bytes and the last 200 lines / 14,000 output bytes per call, compared with
GNU tail in the same shell. Timestamp capture cases are self measurements, with
no external supervisor ratio. `--framing-before OLD --framing-after NEW` selects
the isolated production framing comparison and copy control instead.

Rotation preserves the existing contract: size is checked when opening a log
for a service instance, readiness probe or finish hook, rather than continuously
while an instance writes. Long records can therefore exceed the configured
threshold. Timestamping adds one UTC prefix per LF-delimited record, preserves
NULs and arbitrary payload bytes, and adds no terminating newline. A new service
instance begins a fresh timestamped record.

The implementation batches timestamped records into a 16 KiB output buffer,
handles short writes and `EINTR`, and uses a bounded pipe drain with readiness
polling. A failed timestamp sink is remembered while the supervisor continues to
drain and reap its child; `once` fails and an asynchronous supervisor publishes
`log-failed errno=...`. Log open failures prevent service launch. Shutdown drains
while waiting for TERM, escalates to KILL after two seconds, and removes PID
state after reaping. Restart waits for the previous supervisor and finish hook
instead of relying on a one-second sleep.

Stream-tail records now carry byte lengths instead of using fixed 512-byte C
strings. Regular logs retain the reverse-read implementation already present in
the starting source. Empty regular logs use that path too. `-n 0` emits nothing;
malformed, negative and overflowing counts and unknown options fail with status
2. Names `.` and `..` are rejected.

Without timestamping, the service writes directly to its log and its exit status
reports its own write failures. Timestamped capture instead drains the service
pipe even after a sink error, so the child can finish writing its receipt while
`sv` separately reports log failure. Finish hooks retain their direct-output
contract; their exit status does not replace the service exit status.

Fresh starts publish `starting` before checking readiness and oneshot completion,
so a restart cannot consume the previous instance's `down`/`oneshot-ok` state.
Timestamped readiness-probe output and readiness after restart are covered by a
private executable check script.

Finish hooks now use the same explicit environment builder as run scripts. The
Bash executable's exec interposition discarded libc-only `SV_NAME` when the old
finish path called `execl`; the dependency-order oracle exposed two blank
finish names. The fix preserves both the service name and the exit-status
argument. Failed intermediate runs remain in the task's evidence directory.

`bench/sol-sv-paired.py --before OLD --after NEW --output REPORT` interleaves
both builds and GNU tail in one gated measurement. Capture variants launch the
same fixed service script/interpreter and reset both log and receipt before each
sample. This controls drift between separate build rounds. Both bench drivers
require at least seven samples and validate the warm-up too. The isolated copy
control emits fewer bytes than timestamp framing; it is a cost control, not an
equivalent-output reference. These file tests include no `fsync` or disk-durability
measurement.


Measurements on 2026-10-19 used CPU 11, Intel Core i7-9850H, Linux
6.12.111+deb13, GCC 14.2.0, Bash 5.3.15 and GNU tail 9.7. All builds selected
only `sv`, with `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2` and retained
symbols. Each measured variant passed one warm-up and seven samples. The table
uses the interleaved old/new run, with identical fixture hashes, options and
reset rules; wall time includes the shell and, for capture, the identical Python
producer and its receipt. The synthetic catalog file is 40,000 LF records.
Tails of the actual supervised children's logs also match GNU tail in the
focused tests.

| Workload | Input bytes | Output bytes | Before median ms | After median ms | Comparison |
|---|---:|---:|---:|---:|---|
| `sv log`, 29 calls | 2,800,000 (file) | 14,000/call | 5.58 | 5.54 | GNU tail 25.42 ms; sv/tail 0.218 |
| capture-short | 73,728 | 327,680 | 133.65 | 53.47 | 2.50× |
| capture-long | 131,077 | 131,139 | 310.52 | 49.94 | 6.22× |

The original current-build round already showed no historical tail regression:
3.56 ms for sv versus 17.17 ms for GNU tail, ratio 0.207. The later standalone
round measured 5.39/24.44 ms, demonstrating drift between rounds; the table above
therefore uses the interleaved comparison. No speedup against the historical
3.356 ratio is claimed, and the existing reverse-tail algorithm was retained.

In the short-record syscall profile, writes fell from 24,699 to 34 (including
child/receipt writes); the original writes consumed 90.56% of traced syscall
time. The long-record path also stopped sleeping unconditionally between pipe
drains. Tracing is separate from the wall-time samples.

The interleaved production-function profile processed 1,179,648 input bytes /
131,072 records into 5,242,880 timestamped bytes: 289.95 → 63.27 ms
(4.58×). Median system CPU fell from 209.76 to 7.77 ms; the buffered
implementation then spent 56.64 ms of user CPU, making prefix formatting the
remaining substantial cost. The unframed copy control emitted 1,179,648 bytes in
2.79 ms, so this work did not pursue speculative copy optimizations.

Every capture sample validated the child's completed byte-count/SHA-256 receipt,
timestamp grammar, exact timestamp-stripped log payload, stdout and exit status.
The before/after byte totals in the table are identical. Raw distributions,
fixture hashes, environment, syscall profiles and earlier failed regression
runs are preserved with the task receipt in `bench-before.json`,
`bench-final.json`, `paired.json`, `framing.json` and their adjacent logs.
Native fault-injection, ASan/UBSan and the original `large-smoke.py ... sv` checks
all pass on the final build.

Before binary SHA-256:
`1ac1efc612f5f630a87165d29a6958eeeada21b3424b49c5b9e0512c6ac9c43b`.
Final binary SHA-256:
`a4d571c84f4745e43487f5cfe8d332ed017389ac0d83fb5236d28b4c8decfa8e`.
Final `sv.c` SHA-256:
`582734c71c65d5f35b111a851caba5834b3a6063979027f555edcb90f3f44388`.
