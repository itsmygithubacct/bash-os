# tac: reverse records with buffered output

`tac` reverses the records of each input file and writes files in operand
order. Records end at a newline by default; `-s SEP` selects a literal
separator, `-s ''` selects NUL, and `-b` attaches separators before records.
With no file operand, or with `-`, it reads standard input. These are the
[GNU tac record conventions](https://www.gnu.org/software/coreutils/manual/html_node/tac-invocation.html).

```sh
./build.sh --include tac --name tac
out/bash-tac -c 'PATH=; tac "$1"' _ input.txt
out/bash-tac -c 'PATH=; tac -b -s :: "$1"' _ records.txt
```

## Changes

The previous implementation scanned forward one byte at a time, allocated
separate start/end indexes for every record, and emitted records through
Bash's line-buffered stdout. One 423,000-byte input caused 8,061 writes.
The literal path now searches backward with `memrchr`, emits records as it
finds them, and needs no record index arrays. A per-invocation 64 KiB output
buffer reduces that input to seven writes. The separate trace counted 13
reads before and 12 after, including shell startup; tracing was excluded
from timed runs.

Backward matching also fixes overlapping literal separators: on `ababa`
with `-s aba`, the result is `ababa`; with `-b -s aba`, it is `abaab`, matching
GNU. The old results were `baaba` and `ababa`, respectively. Separators longer
than the input now use bounded offset checks without forming a pointer
before the input allocation.

Output writes handle partial writes and interruption through the shared
buffer helper. `/dev/full`, closed stdout and an ignored `SIGPIPE` now return
failure, and a later invocation in the same shell can still succeed.
The helper flushes pending Bash output before its own writes and preserves
terminal line flushing without changing Bash's stdout buffering mode.
Buffer growth also checks size overflow.

Input now uses descriptor reads instead of the shell's shared `stdin` FILE.
That fixes repeated redirected input under musl, where the old EOF indicator
survived redirection, and prevents another builtin's unread buffered bytes
from appearing in a later `tac` call. For example, `head -n1 < first` followed
by `tac < second` previously could include leftover lines from `first`.

## Measurements, 2026-09-08

This is a separate follow-up to the [catalog snapshot](loadables-status.md).
Both builds use the 89-loadable core profile, Bash 5.3.15, GCC 14.2.0,
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, dynamic linking and retained
symbols. The earlier code is at `ef66d799c99812f3132461cea7f00c983c45c98d`.
The [measurement summary](data/tac-benchmarks.json) records binary and source
hashes, fixture hashes, validation counts and every timing range.

Seven samples followed output validation and warm-up on an Intel Core
i7-9850H, Linux 6.12.96, pinned to CPU 11. Each workload interleaved the four
implementations, rotating and reversing their order. A shared lock serialized
benchmark sessions. Timings include shell startup and loop overhead; external
GNU coreutils 9.7 and BusyBox 1.37.0 commands also include their process
launches from the earlier Bash build. Output was redirected to `/dev/null`.
Every included implementation matched GNU output both once and across at
least three repeated invocations before timing.

Other work was active: the host's one-minute load average was 13.00 at the
start and 17.76 at the end. Compare implementations within this run; these
numbers do not establish isolated throughput or static/RISC-V performance.

All times are **median milliseconds per batch**, not per invocation. Speedup
is earlier builtin time divided by current builtin time.

| Workload | Input bytes | Calls | Earlier ms | Current ms | GNU ms | BusyBox ms | Speedup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Text | 423,000 | 26 | 126.900 | 13.096 | 73.421 | 271.087 | 9.69× |
| Tiny text | 23 | 200 | 9.509 | 10.798 | 392.272 | 442.859 | 0.88× |
| Text, 1 MiB | 1,048,576 | 10 | 139.024 | 17.100 | 47.505 | 246.487 | 8.13× |
| Text, 16 MiB | 16,777,216 | 1 | 200.720 | 24.384 | 34.745 | 270.775 | 8.23× |
| Two-byte lines | 1,048,576 | 2 | 369.127 | 28.631 | 21.337 | 609.381 | 12.89× |
| Three long records | 3,145,730 | 3 | 49.924 | 12.403 | 25.351 | 77.352 | 4.03× |
| NUL records, `-s ''` | 1,048,576 | 6 | 76.784 | 28.037 | 38.985 | — | 2.74× |
| Custom separator, `-b -s ::` | 400,000 | 10 | 54.674 | 26.176 | 45.603 | — | 2.09× |
| Text, `-b` | 423,000 | 26 | 232.796 | 15.443 | 65.336 | — | 15.07× |

For the original text workload, earlier times ranged from 116.001 to
141.310 ms and current times from 10.616 to 17.343 ms: a 9.69× median
improvement. The tiny fixture has overlapping ranges (7.084–14.248 versus
6.427–12.820 ms), so no tiny-input improvement is claimed. GNU's dense-line
median was lower than the current builtin's; their ranges also overlap.
BusyBox has no separator options in this build and is omitted for those rows.

The fixture generator uses the catalog's fixed text seed, repeats/truncates
that text for the larger sizes, and also exercises two-byte lines, long
records, NUL records and a multi-byte separator. To reproduce:

```sh
# Save the earlier binary before rebuilding the same profile with the change.
python3 bench/tac.py --before /tmp/bash-core-before --after out/bash-core \
  --cpu 0 --runs 7 --output /tmp/tac.json
```

Choose an allowed CPU and serialize this with any other timed runs. The
harness validates outputs before assigning timings; inspect every result's
status. Raw sample logs belong outside Git.

## Validation and remaining work

`tests/tac-parity.py` passes 598 reference and shell-state checks in native
dynamic and static core builds. `tests/tac-sanitize.sh` repeats all 598 with
the replacement under ASan/UBSan. The cases include literal and common regex
separators, overlaps, missing final separators, binary input, long records,
64 KiB boundaries, multiple files, repeated stdin, pipe input, terminal output
ordering, read failures, write failures and recovery in a persistent shell.
`tests/run.sh` runs the suite in native, static and sanitizer configurations.

All 598 also pass in the static RISC-V musl core build under QEMU with
`-cpu thead-c906`, matching the SDK's target CPU. Each native/static/RISC-V
binary passed the exact 89-loadable selection check. The RISC-V suite is
also wired into `tests/cross-smoke.sh`; these are execution checks, with no
emulated timing comparison. An exact `tac`-only build skips the one regression
that uses the stock `head` builtin to leave unread stdio input.

Each input is still read completely before output, using memory proportional
to file size. A seekable-file path that reads backward in bounded blocks,
with a spool strategy for pipes, is future work. Multi-byte literal matching
can also repeat comparisons for adversarial prefixes.

Regex matching retains the existing forward POSIX extended-regex engine and
record indexes. Its dialect, matching direction, newline and embedded-NUL
behavior are not fully GNU-compatible. For example, `-r -s '[,:]+'` on
`a,b::c` produces `cb::a,` here and `c:b:a,` with GNU; `-r -s .` also differs
on newlines. Regex conformance needs its own explicit scope and fixtures.
The selected literal performance work is complete; memory use and regex
compatibility remain the next `tac` targets.
