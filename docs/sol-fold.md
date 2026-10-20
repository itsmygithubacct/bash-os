# Fold completion qualification

Stdin duplication reserves descriptors 0–2. `tests/review-fold-descriptors.py` checks that closed output fails without modifying read/write stdin, including repeated calls and descriptor cleanup.

The measurements below predate this review correction. They describe the original
worker implementation; they are not measurements of the corrected code. No new
performance claim is made for this correction.

This work qualifies strict UTF-8 decoding and incremental input delivery in
`loadables/fold.c`. It retains the existing options, ASCII span processing,
word wrapping, per-file column reset, descriptor ownership, and output error
handling. No common helper changes are needed.

Byte mode extends the existing ASCII span path to every byte except newline,
including non-ASCII and controls. Its span scan records both spaces and tabs
for `-s`; other modes retain the ASCII-only shortcut.

## Counting contract

| Input | `-b` | `-c` | Display columns |
| --- | --- | --- | --- |
| Valid UTF-8 scalar | Each byte counts one; wrapping may split it | One unit | Active locale's `wcwidth`, negative widths replaced by one |
| Malformed byte | One | One | One |
| Incomplete sequence at EOF | Each remaining byte counts one | Each remaining byte counts one | Each remaining byte counts one |
| Sequence split across reads | Byte independent | Wait only for missing continuation bytes | Wait only for missing continuation bytes |
| NUL | One | One | Zero |
| TAB / BS / CR | Each counts one | Tab stop / rewind last character / reset | Tab stop / rewind last character width / reset |

UTF-8 grouping is independent of locale. Only Unicode scalar values in their
shortest encoding are valid: overlong encodings, surrogates, values above
U+10FFFF, illegal leads, and stray continuations are preserved as individual
bytes. An invalid byte cannot become a decoded NUL, newline, space, tab, or
other control. Newline always ends a line. The last `-b`/`-c` option wins.

A scalar wider than the selected width is accepted on an otherwise empty
line. Combining marks are separate scalars: zero display width in the tested
UTF-8 locale, one character in `-c`. Wrapping follows scalar widths, not
grapheme clusters. Only ASCII space/tab are `-s` opportunities. In locale C,
non-ASCII scalars still group, but unsupported `wcwidth` values count one.

Input uses 8 KiB `read` chunks and at most three carried UTF-8 prefix bytes.
A refill happens only after consuming available input, or on a potentially
valid incomplete sequence. Completed output is flushed before the next
blocking read, including output to a pipe; terminal output also retains its
newline flushing. Pending input without a newline or an overflowing unit can
remain buffered: this is line folding, not an unbuffered byte copier. A
producer that leaves a valid UTF-8 prefix incomplete must supply its
continuations or EOF. An already-invalid prefix needs no speculative bytes.

## Coverage and references

`tests/fold-parity.py` retains the GNU/BusyBox supported-option comparisons,
binary byte comparisons, long records, refill boundaries, invalid options,
repeated redirects, descriptor cleanup, read failures, `/dev/full`, closed
stdout, ignored SIGPIPE, output order, and PTY output checks.

`tests/sol-fold-check.py` uses Python's strict UTF-8 codec with surrogateescape
to provide independent per-byte recovery. Its column oracle uses Python
Unicode properties for the exercised repertoire. It covers all six
counting/space combinations, widths 1/3/8/40, C and C.UTF-8, scalar-range and
encoding-length boundaries, malformed/truncated input, mixed deterministic
records, refill splits, every two-byte combination, and canonical encodings
of every non-ASCII Unicode scalar in character mode.
Open-producer tests use correctness deadlines and keep input open until the
required output arrives, with no block-size padding. They exercise output to
pipes and private PTYs, every continuation split of 2/3/4-byte sequences,
malformed bytes, EOF truncation, and short canonical-terminal input.

GNU coreutils 9.7 folds UTF-8 as bytes in the tested locales and rejects `-c`.
Its byte mode and ASCII display-column behavior are independent parity
references. Unicode display/character behavior is compared to the independent
oracle, with no GNU performance ratio for different semantics. Locale width
tables, emoji grapheme rendering, and other platforms' terminal rendering
are outside the scalar-width contract.

## Reproduction

The targeted build includes `fold,head,sed,expand,nl,pr,tac,bc` to run the
existing mixed-reader integration test. Fold itself requires no companion
loadables. The selection resolves `_jsmn` for the companion commands.

```sh
python3 "$GATE" build -- ./build.sh --include fold,head,sed,expand,nl,pr,tac,bc --name sol-fold --no-strip
python3 tests/fold-parity.py out/bash-sol-fold
python3 tests/sol-fold-check.py out/bash-sol-fold
python3 tests/input-lifetime.py out/bash-sol-fold
python3 "$GATE" build -- bash tests/fold-sanitize.sh out/bash-sol-fold
python3 "$GATE" bench -- python3 bench/sol-fold.py --binary out/bash-sol-fold --cpu 11 --runs 7 --output "$RESULTS/after.json"
```

`GATE` denotes the campaign's `scripts/gated.py`. Keep raw logs and JSON reports
in the assigned evidence directory. The benchmark requires at least seven
samples and checks every invocation's output and exit status, including the
warm-up. It records affinity, source/binary/fixture/oracle hashes, versions,
work counts, individual samples, medians, and ranges. Each pass reopens the
same fixture in a persistent shell; output is captured in a private regular
file. Timings include startup and GNU fork/exec, while validation is outside
the timed interval. Input fixtures are ASCII (the unchanged catalog text
generator) and mixed accented/wide/combining/emoji text, at 64, 4,096, 423,000,
and 4,230,000 bytes. UTF-8 truncation at a fixture boundary follows the same
strict byte-recovery contract.

Use a fresh output filename for every measurement invocation. Raw reports are
preserved separately; the historical tables in `docs/fold.md` remain historical.

## Current correctness qualification

The unchanged production baseline at `3a48b479e27a0b96c04aa2908f16b4a1a38eae12`
passed the existing 2,651 checks. The new oracle suite failed on malformed
UTF-8 character counting, and the open-producer suite failed when `a\n`
produced no output before its deadline. These expected baseline failures are
retained in the evidence receipts.

The final native build passes 2,693 parity/option/state checks, 135,311
independent-oracle cases and streaming checks, and 156 mixed-reader/descriptor
checks. The real Bash module under ASan/UBSan passes both fold suites with the
same counts. The scalar enumeration checks all 1,111,936 non-ASCII scalar
encodings in each locale; the case count includes those as two aggregate
vectors. Bash-wide leak detection is disabled by the existing sanitizer
runner. No sanitizer diagnostic was reported.

The additional parity cases keep a producer open after a prefix that is
already invalid (`C0`, `E0 80`, `ED A0`, `F0 80`, `F4 90`, `F5`, or `E2 58`).
Each prefix must force the pending width-three line to wrap immediately,
without receiving its nominal sequence length. These run in all six modes.

The full shared `repeat-input-check.sh` is not run against this eight-command
build because it requires unrelated loadables. Its fold requirement is
covered more strongly here by byte-exact repeated/distinct input checks,
FD comparisons, mixed-reader integration, and recovery after output errors.

## Current performance qualification

The benchmark uses Bash 5.3.15, GCC 14.2.0, native dynamic builds with
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2` and retained symbols on an
Intel Core i7-9850H, Linux 6.12.111, glibc 2.41. All runs use CPU 11 and the
campaign gate. The 423,000-byte ASCII fixture hash remains
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`.

The baseline's previously measured ASCII case reproduced at 17.062 ms versus
GNU's 38.671 ms for nine calls, so the historical ASCII slowdown is absent.
The new large Unicode byte case exposed a remaining general-loop cost:
83.231 ms versus GNU's 64.771 ms for three calls. Extending the byte span
scanner removed that per-unit path. A first after-run also exposed an ASCII
regression from testing the counting mode inside the scan; the final source
selects separate byte/ASCII loops once per span. The first after-run is
retained separately as `after.json`, not substituted for the final report.

Final results use `before.json` and `after-v2.json`; all 16 workloads in
each report have status `ok` for every implementation. The harness and oracle
hashes, fixture/expected-output hashes, options, passes, tool versions and
CPU affinity match. Every timing below is batch milliseconds, median
(minimum–maximum) over seven samples after one validated warm-up.

| Case | Calls | Baseline builtin | Final builtin | Final GNU |
| --- | ---: | ---: | ---: | ---: |
| ascii-64 | 128 | 4.361 (3.915–5.259) | 4.945 (4.694–5.437) | 110.662 (103.480–123.206) |
| unicode-byte-64 | 128 | 5.548 (5.130–6.917) | 5.600 (4.961–5.714) | 118.760 (117.230–133.997) |
| unicode-column-64 | 128 | 5.045 (4.969–6.673) | 5.508 (5.359–5.625) | — |
| unicode-character-64 | 128 | 5.330 (4.978–5.571) | 5.713 (4.736–6.011) | — |
| ascii-4096 | 32 | 4.001 (3.883–4.277) | 4.572 (4.383–4.735) | 38.317 (36.863–39.726) |
| unicode-byte-4096 | 32 | 5.238 (4.952–6.876) | 4.141 (4.034–4.817) | 35.384 (34.694–35.605) |
| unicode-column-4096 | 32 | 5.041 (4.921–5.134) | 4.675 (4.443–4.824) | — |
| unicode-character-4096 | 32 | 4.958 (4.872–6.547) | 4.404 (4.288–4.659) | — |
| ascii-423000 | 9 | 17.062 (17.026–19.609) | 17.983 (17.547–20.852) | 32.876 (31.822–34.692) |
| unicode-byte-423000 | 9 | 29.562 (26.789–32.634) | 14.970 (14.024–23.028) | 32.194 (31.466–33.067) |
| unicode-column-423000 | 9 | 26.795 (24.361–27.286) | 30.520 (30.128–33.244) | — |
| unicode-character-423000 | 9 | 23.702 (23.513–23.866) | 26.710 (25.692–27.382) | — |
| ascii-4230000 | 3 | 48.044 (45.990–49.816) | 49.851 (49.448–56.315) | 73.685 (73.224–87.449) |
| unicode-byte-4230000 | 3 | 83.231 (78.511–88.200) | 37.761 (35.642–43.566) | 64.442 (63.105–74.695) |
| unicode-column-4230000 | 3 | 64.226 (63.318–70.081) | 77.952 (71.190–82.413) | — |
| unicode-character-4230000 | 3 | 65.968 (62.926–67.319) | 71.979 (67.829–89.427) | — |

The final large Unicode byte case is 2.20× faster than the paired baseline
and takes 0.586× GNU time. Large ASCII is 3.8% above the baseline median;
the 423 KB ASCII case is 5.4% above it. Large Unicode column and character
cases are 21.4% and 9.1% above their baseline medians. These are measured
tradeoffs of the decoder/refill/scan changes, not a claim of uniform speedup.
Tiny cases include shell/call overhead and should not be treated as isolated
decoder throughput. The builtin remains faster than GNU for every matched
final workload. Other work was active. One-minute load snapshots at start/end were
2.79/2.86 for the baseline and 2.67/2.81 for the final run.

For three large Unicode byte calls, all seven syscall profiles agree:

| Build/tool | `read` calls | `write` calls |
| --- | ---: | ---: |
| Baseline | 3,106 | 195 |
| Final | 1,558 | 1,554 |
| GNU | 3,115 | 3,099 |

The raw-read refill halves input syscalls on this fixture. Flushing before
a refill increases output syscalls, providing the required open-producer
delivery. Together with byte spans, these changes improve byte-mode time;
the profiles do not isolate a percentage for each change. Hardware
`cycles,instructions` counters were rejected with exit 255 because
`perf_event_paranoid=3`. That diagnostic is explicitly unavailable; no host
setting was changed. Syscall profiles are diagnostics, and their instrumented
durations are not used as throughput numbers.

```sh
python3 "$GATE" bench -- python3 bench/sol-fold-profile.py \
  --before "$BEFORE_BINARY" --after out/bash-sol-fold --cpu 11 \
  --output "$RESULTS/profiles.json"
```

Raw evidence remains in the assigned task directory: `before.json`,
`after.json` (intermediate), `after-v2.json` (final), `profiles.json`,
`profiles-v2.json`, their individual trace files, and command/exit-code logs.
Timing reports carry source/binary hashes; profiling reports carry binary
hashes. Production fold snapshots and all three measured binaries are
retained alongside them.

| Artifact | SHA-256 |
| --- | --- |
| Baseline fold source | `dfe1cff3ab54c9d67dd2f62181718ba71a95bd15f3f32e9f70e9b607c783a6d4` |
| Final fold source | `bd9a0b5042319e7d3b8b8103204ca04c8d37be39e439ab6862f23e5f12e30713` |
| Baseline binary | `b36da70163a8a19fb0398adff4529e4b109364a439eb6c7eedf1e8f970ccf12b` |
| Final binary | `022cfaa5a5b4bb4bf9874133cc4431d679c3d21d676c0f63b4318b00317bd487` |

Qualification covers the native software path and scalar-width contract.
It does not establish current appliance/cross-architecture throughput or
grapheme-cluster terminal rendering. GNU 9.7 has no matching Unicode
column/character interface, so those rows have no external ratio.
