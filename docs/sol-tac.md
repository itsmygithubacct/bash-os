# tac bounded-input and GNU regex follow-up

Literal separators now use backward `pread` blocks. The scanner allocates
64 KiB plus the separator length and retains record offsets, including for a
record much larger than the block. Output copies each record forward through
a separate fixed buffer; a growing record never forces input-buffer growth.
Read windows overlap by the separator length minus one, preserving matches
split across a read edge and GNU's rightmost, non-overlapping literal matches.
The existing 64 KiB output helper is unchanged.

Pipes use a private `mkstemp` file in exported `TMPDIR` (default `/tmp`). The
pathname is immediately unlinked and the descriptor closed on success and
all ordinary failures. The spool consumes disk space proportional to input;
input size does not determine the literal scanner's memory. The caller owns
stdin; opened operands and spools have independent ownership even when an
opened operand reuses descriptor zero. Seekable stdin is processed from its
beginning for each `-` operand, matching GNU tac even after a shell `read`.
Zero-size special files that supply data use the spool path.

GNU tac uses Emacs regex syntax and searches for the rightmost starting
position in each remaining prefix. This makes `[,:]+` on `a,b::c` produce
`c:b:a,`. Dot excludes newline and includes NUL. Empty matches participate
in record boundaries; an empty regex argument is an error. Escaped grouping
and alternation work, while unescaped parentheses and `|` are literal. These
behaviors follow the [GNU implementation](https://github.com/coreutils/coreutils/blob/master/src/tac.c).

In a single-byte locale, dot and simple bracket atoms, optionally followed
by `*`, `+` or `?`, use a fixed 64 KiB backward scanner. For example, a
rightmost `[,:]+` match has length one; the repeated form needs no growing
right context. Regexes with no metacharacters use the literal scanner.
These paths also build on libcs without the GNU regex API. On glibc, all
other expressions use length-aware `re_compile_pattern` / `re_search` with
Emacs syntax, exact binary input and backward matching. Compilation restores
the process's previous regex syntax, preserving Bash's own regex operations.

## Remaining limits

The general regex path maps the complete file and delegates to GNU's regex
engine. Its address space and working memory are **not bounded independently
of input size**, and it rejects input above `INT_MAX` bytes instead of
truncating offsets. General regexes on libcs without the GNU API return an
explicit unsupported-pattern error; they no longer silently use a different
POSIX ERE dialect. A portable GNU-compatible matcher with bounded working
storage remains required for full completion. This work does not claim that
all regex input sizes, locales or musl expressions are complete.

Multi-byte literal matching can still repeat comparisons for adversarial
separator prefixes. Concurrently truncated or modified regular files are
not a stable-input parity contract; a short positional read reports failure.

## Validation and measurement

`tests/tac-parity.py` retains its existing byte, input-lifetime, terminal,
output-error and recovery assertions. `tests/sol-tac-parity.py` adds large
records, oversized and split separators, GNU regex direction/syntax/anchors,
newlines and NULs, repeated seekable stdin, spool errors and cleanup, FD
ownership, persistent regex state and address-space-limited literal and byte-atom regex cases.
`tests/sol-tac-mapped.sh` runs the original tac assertions extracted from the
shared text-tools and repeat-input suites. `tests/input-lifetime.py` runs
unchanged with the eight-reader selection. No shared test registration or
catalog files are changed.

`bench/sol-tac.py` measures the exact historical 423,000-byte fixture with
26 calls, the reviewed 63-call redirected-input workload, and literal,
huge-record and regex workloads at 1, 4 and 16 MiB.
It checks exact GNU bytes and status on the warm-up and all seven samples,
including every repeated pass, and records maximum per-process peak RSS, CPU affinity,
fixture/source/binary hashes and versions. Pipe timings include one owned
`cat` producer per call on both sides. Output goes to an owned file and is
hashed outside the timed interval. Timings therefore include output file
writes, the small C resource launcher and shell startup, and differ from historical
`/dev/null` measurements. Invalid old regex outputs receive no ratio.

Build only `tac,head,sed,fold,expand,nl,pr,bc` for the existing mixed-reader
checks; tac itself requires no companion loadables or shared helper changes.
Run compilation and measurement commands through the campaign resource gates.
Raw reports and command logs belong in the task evidence directory.

Build `bench/sol-tac-rusage.c` separately with `cc -O2 -Wall -Wextra
bench/sol-tac-rusage.c -o out/sol-tac-rusage`, using the build gate. This small
launcher collects `wait4` counters after forking from its own small address
space, excluding the Python fixture generator's heap from the child's
pre-exec RSS high-water mark. RSS is the maximum for one process in the
waited-for tree, not summed memory for concurrent producer/consumer processes.
The measurement driver never builds its dependencies.

The `regex-general` workload searches for `BEGIN.*END` without a match in
the huge-record fixture. It measures a full general-regex scan, not dense
general-regex matches or an arbitrarily long matching separator. The separate
byte-atom workload has adjacent separators and exercises reverse matching.

Before timing a regex option, the driver checks a small independent binary
probe. An implementation that fails it is marked invalid for that option at
all sizes and receives no full-size timing. The original forward `regexec`
implementation is excluded this way for `[,:]+`; an earlier 16 MiB validation
attempt exceeded 120 seconds because that path repeatedly calls
[`regexec`, which computes `strlen`](https://github.com/bminor/glibc/blob/master/posix/regexec.c),
on successive suffixes. Its partial report is retained separately.
The timeout path now kills the entire owned sample process group.

## Measured results

Native x86-64, glibc 2.41, Bash 5.3.15, GCC 14.2.0 and GNU tac 9.7,
pinned to CPU 11 on an Intel i7-9850H. Both builds select the same eight
readers with `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`. All 23
replacement cases pass the GNU byte/status oracle on the warm-up and all
seven samples. The original implementation has 17 validated cases; its six
byte-atom regex cases fail the independent probe and have no timing comparison.

File-input medians in milliseconds and maximum sampled per-process RSS in KiB:

| Input MiB | Literal ms / RSS | `[,:]+` ms / RSS | General no-match ms / RSS |
| ---: | ---: | ---: | ---: |
| 1 | 4.39 / 3,564 | 6.16 / 3,576 | 47.69 / 4,384 |
| 4 | 8.75 / 3,536 | 16.58 / 3,540 | 178.80 / 7,548 |
| 16 | 29.69 / 3,480 | 69.48 / 3,536 | 791.35 / 19,728 |

At 16 MiB the corresponding GNU medians are 38.61, 821.19 and 760.74 ms.
The literal path's original peak was 19,792 KiB versus 3,480 KiB now. For
huge individual records, the file path falls from 19,840 to 3,588 KiB and
the pipe path from 18,112 to 3,448 KiB. The pipe spool has an I/O cost: the
16 MiB huge-record median is 25.19 ms versus the original 20.66 ms.

The general no-match fallback remains input-dependent: 19,728 KiB at 16 MiB.
Its median is 791.35 ms versus the original 225.56 ms and GNU's 760.74 ms.
GNU compatibility on this path costs CPU relative to the earlier forward
POSIX implementation; no general-regex performance completion is claimed.

The reviewed 63-call text workload takes 22.84 ms versus GNU's 75.51 ms in
the replacement run. The original run recorded 27.73 and 91.99 ms respectively.
The 26-call workload takes 11.76 ms versus GNU's 32.50 ms. Before and after
runs were sequential, while each run interleaved the builtin and GNU; host
load changed, so these figures do not establish a paired before/after speedup.
Raw reports retain every sample, min/max, hashes, fixture options and counters.

The raw qualified reports are `measured-qualified-before.json` and
`measured-qualified-after.json` in the task evidence directory. The separate
`measurement-inspection.log` confirms every per-case status and matching
fixture, binary, source, driver and reference metadata. Historical reports
remain unchanged.

Final correctness runs pass 598 original tac checks, 156 unchanged mixed-reader
checks, five extracted shared-suite tac checks, and 810 focused checks. The
production replacement under ASan/UBSan passes the original 598 and all 806
focused checks applicable to sanitizer execution. The four 48 MiB / 32 MiB
address-space checks run only in the native suite. The final focused cases
include every split of two multi-byte separators across the exact first read
edge, in both attachment modes and with both files and pipes.
