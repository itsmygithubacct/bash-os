# unexpand completion

The builtin converts initial blanks by default, and all blanks with `-a` or
`-t`. `--first-only` takes precedence regardless of option order. Tab lists
accept comma or space separators, uniform widths, finite explicit stops,
trailing `/N` aligned to column zero, and trailing `+N` relative to the last
explicit stop. Empty tab arguments retain the default. Operands form one
continuous byte stream, including pending blanks across unterminated files.
Missing files and read errors report failure while later readable operands
are processed. Write errors stop processing and return 1.

`tests/unexpand-check.sh` retains its GNU and held-producer write-failure
checks; its comparisons preserve trailing newlines and NUL bytes.
`tests/sol-unexpand-parity.py` adds exact GNU stdout/status checks for pipe and
regular-file input, initial/all conversion, option precedence, stop forms,
backspaces and other controls, all byte values, long records, buffer edges,
multiple operands and repeated stdin. It also checks invalid arguments,
empty PATH, output failure recovery, closed output, ignored-SIGPIPE failures,
terminal line delivery, shell state and descriptor cleanup.
`tests/sol-unexpand-sanitize.sh` compiles the production source as an
ASan/UBSan module and runs the same cases; run it through the build gate.

The supported software scope is byte-oriented conversion in the C locale
on the native Linux Bash build.
Tab widths are bounded by
`INT_MAX` and explicit lists by 64 stops. Invalid CLI arguments use Bash's
usage status 2; GNU uses 1. Diagnostic prefixes/help/version text are specific
to the builtin. These bounds and text differences are not full GNU CLI
conformance. Options precede file operands. Other locales are not qualified
by this C-locale suite. No hardware qualification is needed.

`bench/sol-unexpand.py` measures `-a` on tiny input, the historical 440,000-byte
spaces fixture with nine passes, a 4,400,000-byte variant, a million-byte
blank run, and binary/control records. Every pass writes a separate output
file; exact bytes, stderr and all exit statuses are checked after timing.
Each implementation gets a warm-up and seven samples in alternating order.
The same shell launches the builtin and absolute GNU executable with empty
PATH. Redirections reopen the fixture and truncate each output on every call.
Output-file creation and shell startup are included. `/dev/full` checks run
outside timing for every case and implementation. Reports include all samples,
fixture/source/binary SHA-256, versions, CPU affinity and work counts. This
method includes output-file costs and cannot be numerically equated to the
historical snapshot's `/dev/null` timings on a different build/host.

Validation and measurement results are recorded in the task receipt and its
raw evidence directory. Shared catalog files and historical reports are not
rewritten by this task.

The reproduced starting build already buffers regular-file input and output
in 64 KiB blocks. On an i7-9850H, pinned to CPU 11, using Bash 5.3.15,
GCC 14.2 and GNU coreutils 9.7, it took 20.44 ms versus GNU's 41.12 ms on the
historical fixture (seven samples, nine passes each). Its builtin/GNU median
ratios were 0.087 for tiny input, 0.497 for the historical fixture, 0.545 for
the large variant, 0.384 for long blanks and 0.402 for binary/control records.
These results reproduce current validated work; they do not establish a
speedup over the historical 1.99 ratio. That slowdown was not reproduced,
and the existing regular-file buffering and ordinary-byte fast paths are
retained.

A separate gprofng attempt validated all 400 passes, but reported that its
sampling timer changed from 997 microseconds to zero. Its seven samples
cannot support CPU hotspot percentages. `bench/sol-unexpand-profile.py`
collects syscall counts with strace in separate runs, validating all nine
passes for each implementation. Its traced times are not performance ratios.

The final builtin passes all 541 focused checks both natively and with
ASan/UBSan, plus all seven retained checks. This includes large pending blank
buffers with widths 65,537 and `INT_MAX`, legacy numeric options and their
interaction with modern stop lists. Held blank producers also stop on output failure before EOF, with the same
assertion run against GNU. Regular files retain block buffering; pipes keep
stdio output buffering, and terminals keep line delivery. The configured build selects only
`unexpand`; no companion loadables or common-helper changes are required.

The broader workloads exposed a conversion cost on long blank runs in the
first corrected candidate. Consecutive pending spaces are now accumulated in
batches bounded by both the next tab stop and the current input block. This
preserves every tab-stop transition and the pipe/terminal I/O behavior.
An interleaved comparison isolating batching before the stdin-lifetime fix
measured 18.76 ms before this optimization and
9.34 ms after it on the long-blank batch, a 2.01x improvement. The retained
starting build took 15.60 ms in that same run. Separate nine-call traces
showed identical 164 reads and 27 writes before and after the optimization,
supporting conversion work as the source of the gain. These counts include
shell startup and status writes; traced times are not used for ratios.

Final interleaved medians (including stdin isolation), milliseconds per batch,
after a warm-up and seven
samples on CPU 11:

| fixture | input bytes/call | calls/batch | starting builtin | final builtin | GNU | final/GNU |
|---|---:|---:|---:|---:|---:|---:|
| tiny | 22 | 300 | 28.69 | 35.22 | 347.57 | 0.101 |
| historical spaces | 440,000 | 9 | 31.54 | 29.88 | 62.59 | 0.477 |
| large spaces | 4,400,000 | 3 | 92.46 | 89.43 | 171.17 | 0.522 |
| long blanks | 1,000,002 | 3 | 26.54 | 15.33 | 69.90 | 0.219 |
| binary/control bytes | 542,000 | 3 | 6.96 | 6.33 | 18.30 | 0.346 |

All four implementations in this run (starting builtin, corrected candidate
before batching, final builtin and GNU) passed every per-pass byte/status
check, including warm-ups. Each also returned exactly 1 on `/dev/full` for
every fixture outside timing. Historical-fixture syscall batches used 83
reads and 63 writes for the builtin, versus 992 and 765 for GNU. The syscall
counts include shell startup and status writes. Raw samples, hashes,
validation records and traces remain in the task evidence directory; these
figures do not replace or merge historical datasets.

Each invocation now owns its stdin stream through a private descriptor above
the standard descriptors. Failed pipe reads/output cannot leave stdio
read-ahead for a subsequent redirection, and closed stdout remains closed
even when stdin is read/write. Three pipe-failure/recovery sequences and an
unchanged-input assertion for closed stdout cover these cases. The private
descriptor is closed on success, error and Bash unwind; stdin itself stays
open. No shared helper was changed.

This ownership adds per-call descriptor/stdio setup. In the final tiny batch,
the builtin took 35.22 ms versus the starting build's 28.69 ms for 300 calls
(23% more, about 22 microseconds/call), while GNU took 347.57 ms. This is a
measured cost of error recovery and descriptor isolation. In the same final
run, long blanks improved 2.04x against the unbatched corrected candidate
and 1.73x against the starting build. Every comparison uses matched work
within its own interleaved run; cross-run wall times are not speedup claims.
