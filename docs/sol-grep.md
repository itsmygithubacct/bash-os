# grep: PCRE2 and focused completion

`grep` implements BRE (default and `-G`), ERE (`-E`), fixed strings (`-F`),
and PCRE2 (`-P`) inside Bash. It never delegates to an external grep.
Selecting `grep` now requires the PCRE2 development headers and `libpcre2-8`
version 10.34 or newer. `config/helpers.json` supplies `-lpcre2-8` automatically.
Static builds need the static archive; cross builds need matching target
headers and libraries, supplied with the normal `--deps-prefix` mechanism.
The separate `pcre` command is not a required companion. There is no disabled
`-P` default or silent fallback to POSIX regex.

PCRE patterns preserve capture numbering, leading control verbs, lookaround,
and `\K`. `-w` uses boundary lookarounds and lets the engine retry alternatives;
`-x` anchors the engine to the entire record. Both work with NUL records (`-z`).
The `-w` wrapper has GNU's restrictions on leading control verbs and trailing
extended-mode comments; invalid wrapped patterns return 2.
The C locale scans bytes; UTF-8 locales use UTF matching and treat invalid UTF
subject bytes as barriers, following GNU grep. PCRE shorthand classes retain
their ASCII defaults unless the pattern requests Unicode properties.

Statuses are 0 for selected input, 1 for no selection, and 2 for errors.
Invalid PCRE patterns report a PCRE2 compile error with an offset; diagnostic
wording need not match GNU. More than one PCRE pattern is rejected, as in
GNU grep. PCRE2 match/depth-limit failures are errors, never nonmatches.
`BASHPCRE_MATCH_LIMIT` and `BASHPCRE_DEPTH_LIMIT` set positive limits, defaulting
to 1,000,000 and 10,000. Match state is allocated once per call and freed on
success and failure. Patterns compile on every invocation; there is no cache
or JIT compilation.

Seekable stdin is restored after the last selected record under `-m`, relative
to the invocation's starting position, including repeated `-` operands and
trailing context. An unterminated final record leaves stdin at its real EOF.
Repeated `-f -` calls clear stdio EOF state, and pattern-file read errors return
2. Output failure returns 2 and clears the stream error so later calls work.

The existing `tests/grep-parity.sh` assertions remain intact. The additional
`tests/sol-grep-check.py` compares stdout bytes and status against GNU grep in
C and C.UTF-8, including binary/NUL data, PCRE capture/word/line behavior,
context, `-m`, malformed patterns, repeated stdin, `/dev/full`, error recovery,
and descriptor counts. Compile diagnostics are checked by status and presence
of a diagnostic; match limits have a native error assertion. The same single
call cases run against production grep through `tests/grep-host.c` under
ASan+UBSan. `tests/sol-grep-build-harness.sh` builds that harness separately.
`tests/sol-grep-rootfs.sh` checks a targeted static build in an isolated root
containing only Bash and fixtures.

This is bounded parity, not a claim to implement every GNU extension.
Color options remain accepted without emitting color. POSIX regex retains
the C library's embedded-NUL limitations: glibc dot does not match NUL; without
`REG_STARTEND`, POSIX matches cannot span embedded NUL. PCRE2 uses explicit
lengths and does not share those restrictions. Locale validation covers C and
UTF-8, not other multibyte encodings.

`bench/sol-grep.py` reproduces the historical 423,000-byte text fixture and
57-pass ordinary count/line workloads. It adds BRE/ERE and PCRE scan cases
and 200-call empty-input cases. Every warmup and timed pass has independently
computed expected stdout and status, fresh input redirection, fixed CPU
affinity, one warmup and seven interleaved samples. Empty-input results include
shell dispatch, regex compilation and opening input; scan results additionally
include scanning and output. They do not isolate pure regex engine time.
Raw reports record fixture/source/binary hashes, versions and all samples.

Validation on GNU grep 3.11 and PCRE2 10.46 passed all 584 existing comparisons
and 267 additional checks. The static binary passed the empty-PATH host smoke
test and the focused isolated-root test. The sanitizer harness passed all
584 existing comparisons and 237 single-call focused checks under ASan+UBSan
with leak detection. Persistent-shell checks run against the real static Bash
instead of the standalone harness.

The initial dynamic build reproduced the ordinary workloads with no slowdown:
57 count passes took 20.69 ms versus GNU's 76.33 ms; line output took 100.04 ms
versus 144.90 ms. The new BRE/ERE scan workloads took about 1.4 times GNU's
time. Empty-input batches show that compilation/dispatch is a small part of
those scan workloads. No speculative scan optimization was introduced.
The final static build has its own matched GNU comparisons; changing linkage
is not reported as an implementation speedup.

Final medians in milliseconds per batch, pinned to CPU 11 on an Intel
Core i7-9850H, GCC 14.2, Bash 5.3.15, GNU grep 3.11 and PCRE2 10.46:

| workload | calls | builtin ms | GNU ms | builtin/GNU |
|---|---:|---:|---:|---:|
| ordinary count | 57 | 24.924 | 85.183 | 0.293 |
| ordinary lines | 57 | 99.570 | 131.739 | 0.756 |
| ERE scan | 15 | 58.579 | 38.187 | 1.534 |
| ERE empty input | 200 | 11.788 | 195.604 | 0.060 |
| BRE scan | 15 | 58.372 | 37.794 | 1.544 |
| BRE empty input | 200 | 13.217 | 209.633 | 0.063 |
| PCRE lookahead scan | 15 | 76.919 | 33.036 | 2.328 |
| PCRE empty input | 200 | 13.894 | 198.811 | 0.070 |

Each scan call processes 423,000 bytes / 8,062 records. Regex empty-input
calls cost roughly 0.06–0.07 ms each, versus 3.9–5.1 ms for scan calls,
indicating that scan work dominates these regex workloads. This comparison
does not subtract timings or isolate a pure compilation measurement. The PCRE
interpreter preserves both match and depth limits; its measured scan throughput
is below GNU's. Every case passed one warmup and seven samples, validating every
individual call against independent expected bytes and status. Other work was
active on the host; these are matched comparisons, not maximum-throughput claims.

Complete logs, raw distributions, hashes and exact commands are recorded with
the task receipt, outside the repository's historical benchmark datasets.
