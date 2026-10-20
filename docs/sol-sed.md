# sed cycle, regex and shared-input completion

Replacement text also decodes `\r`, `\a`, `\f`, and `\v` to their control
bytes, including with captures and case conversion. The focused suite retains
18 exact GNU comparisons for these and the existing newline/tab escapes.

The measurements below precede the replacement-escape, portable-regex and
framing corrections. They remain
evidence for the original measured source, not timings of the corrected source.

The builtin selects BRE by default and ERE with `-E` or `-r`. Address and
substitution regexes retain their own case/multiline flags. Empty regexes reuse
the most recently evaluated regex, including across file operands; skipping a
command does not select its regex. An empty regex without a previous evaluated
regex fails at execution. Invalid replacement backreferences fail as well.
GNU regex syntax changes are restored before returning to the surrounding shell.

On glibc, matching uses explicit subject lengths and offsets, so embedded NULs
are data, `.` matches them, and word boundaries can inspect the character before
a later substitution offset. Literal substitutions use bounded byte searches.
UTF-8 fixtures also check empty-match and word-boundary behavior. Other libcs
use a private length-aware GNU engine; see [backend provenance and build
notes](sol-sed-regex.md). Native builds can select that path with
`BASHSED_PORTABLE_REGEX` for sanitizer validation.

File operands form one stream: numbering, hold space, address ranges, branch
state and `n`/`N` cycles cross file boundaries. Empty operands do not terminate
the stream. `-s` and `-i` retain independent file cycles. `F` follows the current
operand, including a later empty file visited by `$` lookahead, matching GNU's
observable behavior.
A failed substitution preserves an earlier success until `t`/`T` or new input
clears it. Each invocation releases input/output streams and resets its state.

A reached `$` on a Linux pipe/FIFO uses `tee(2)` into a private pipe to observe
a byte without consuming it. Sockets use `MSG_PEEK`; seekable stdin reconciles
stdio lookahead before closing the duplicate. A producer with no pending bytes
must provide another byte or close before `$` can decide whether the current
line is last. A preceding `q` avoids this dependency. Pipe/terminal input still
uses byte-at-a-time reads, and terminal output retains immediate line delivery.
Terminals and platforms without Linux `tee` use `poll` and `FIONREAD` where
available. These queries leave queued bytes untouched. Readable canonical
terminal EOF markers are recognized when the byte count is zero. A terminal
EOF marker followed by already queued data cannot be distinguished from data
by these queries; exact GNU last-line classification in that case remains a
limitation. Unusual nonseekable devices without a supported peek facility
retain the stdio fallback. Non-Linux execution needs platform qualification.
For raw terminals with `VMIN > 1`, readiness may require more bytes than a
one-byte lookahead. The builtin checks the byte count first and rechecks at
bounded intervals while waiting, preserving the caller's terminal settings.

`q` flushes pending append data and terminates an unterminated printed pattern,
matching GNU. `Q` discards pending appends. `l` reserves its final column for
continuation, accepts a command width and `-l`/`--line-length`, and uses width
zero for no wrapping. `r` and `R` preserve auxiliary bytes, including an
unterminated final record; queues flush before `n`/`N` reads and after `d`.

Attached `-e`/`-f` arguments and long spellings of supported options are
accepted. Script-file read boundaries do not insert script characters.
`-u` disables regular-file output buffering. Invalid options and scripts
return 1; missing input operands return 2; read/write failures return 4.
A quit code cannot erase an earlier I/O failure. Invocation resources are
released before checking Bash's pending interrupt state.

The command remains a GNU sed subset: `-z`, `--posix`, `--sandbox`, `--debug`,
`--follow-symlinks` and `--version` are not implemented, and execution still requires
`BASHSED_ALLOW_EXEC=1`. Numeric overflow is rejected instead of saturated;
in-place backup suffixes remain bounded and literal. Script files containing
literal NUL are not supported; use numeric escapes in regex and replacement
text. This is not a full GNU command-line or locale-collation equivalence claim.

## Validation

The focused build selects `sed,head,fold,expand,nl,pr,tac,bc`: sed needs no helper
or required companion; the others serve the existing input-lifetime integration
suite. Build commands, including sanitizer compilation, must use the campaign
build gate. Measurements must use its bench gate.

```
python3 "$CAMPAIGN_SCRIPTS/gated.py" build -- \
  ./build.sh --include sed,head,fold,expand,nl,pr,tac,bc --name sol-sed
python3 tests/sol-sed-parity.py out/bash-sol-sed
python3 tests/sol-sed-complete.py out/bash-sol-sed
python3 tests/sol-sed-binary-regex.py out/bash-sol-sed
python3 tests/sol-sed-signals.py out/bash-sol-sed
python3 tests/head-sed-parity.py out/bash-sol-sed
python3 tests/sed-streams.py out/bash-sol-sed
python3 tests/input-lifetime.py out/bash-sol-sed
python3 "$CAMPAIGN_SCRIPTS/gated.py" build -- \
  bash tests/sol-sed-sanitize.sh out/bash-sol-sed
python3 "$CAMPAIGN_SCRIPTS/gated.py" bench -- \
  python3 bench/sol-sed.py out/bash-sol-sed REPORT.json
```

The new suite compares GNU output bytes for dialects, captures, empty regexes,
multifile cycles, final newlines, binary subjects, in-place backups and errors.
It checks exact shared file offsets and the full suffix left in an open pipe,
including a NUL lookahead byte. Persistent-shell loops mix failures with normal
calls under a low descriptor limit, with empty PATH. A private PTY checks line
flushes while the input producer stays open. Existing parity and stream-delivery
assertions are retained; the sanitizer runner also executes the new suite.

The task benchmark uses the historical deterministic 423,000-byte fixture and
8 substitutions per batch, plus branch and multifile workloads. Expected bytes
come from independent Python transformations and must agree with GNU before a
variant is timed. One warmup and seven samples use fixed CPU affinity; every
pass's status and complete bytes are checked. Output capture goes to a
fresh temporary regular file per pass, so these numbers must not be paired
with historical `/dev/null` timings. Raw receipts record source/binary/fixture hashes, versions,
environment, work counts and complete sample distributions.

Native x86-64 glibc validation passed 258 new checks, 974 existing head/sed
checks, 8 live-stream checks and 156 mixed-reader checks. ASan/UBSan passed
both the 974-check existing suite and the 258-check new suite. No global suite
or full-profile build was run. The original run did not qualify non-glibc GNU binary regexes;
these historical results qualify the earlier Linux/glibc implementation;
they do not measure or qualify subsequent corrections.

## Current correction checks

The correction passes 977 head/sed parity checks, 276 focused cycle/regex
checks, 312 framing/CLI/terminal checks, 1,008 binary regex comparisons, 12
owned-process signal checks, 8 stream checks and 156 mixed-reader checks.
These passed on linked glibc, static native musl 1.2.5, static RISC-V musl
under QEMU user-mode emulation, the forced portable regex/peek module, and
ASan/UBSan modules for both backends. Sanitizer leak detection is disabled
because the hosting Bash is not instrumented. The native musl binary also
passed `tests/sol-sed-rootfs.py` in a private root containing only that binary,
with an empty PATH. No physical RISC-V hardware was used; QEMU 10.0.13 ran on
the Linux x86-64 host. No non-Linux execution environment was available.

The separate `tests/sol-sed-terminal-eof.py` oracle remains a strict failure:
with a canonical EOF marker before already queued terminal bytes, `$` cannot
classify the current line correctly through `poll`/`FIONREAD`. It fails on
all three final linked platform variants. The original stdio lookahead
classified this EOF case correctly but lost ordinary lookahead bytes.
The ordinary canonical/raw terminal cases verify that subsequent readers retain every
byte, including NUL. These passing cases do not close the EOF-ordering gap.
The forced portable peek checks run on Linux and do not qualify another
kernel. Do not register the strict failure as a passing or skipped test.

## Corrected native measurements

The final glibc and musl 1.2.5 binaries were measured on Intel Core i7-9850H,
Linux x86-64, CPU 11, GCC 14.2, Bash 5.3.15 and GNU sed 4.9. Each cell is
milliseconds for eight calls: median and min–max across seven samples after
a validated warmup. Every invocation's status and complete output bytes
matched the independent oracle. Fixtures, regular-file output and work units
are described above. These are separate paired runs for each libc, not an
interleaved libc comparison.

| Backend | Workload | Builtin ms | GNU ms | Builtin / GNU |
|---|---|---:|---:|---:|
| glibc | Historical substitution | 36.259 (30.224–54.680) | 106.627 (102.215–131.960) | 0.340 |
| glibc | Substitution/branch loop | 118.514 (105.865–196.926) | 205.216 (196.817–351.798) | 0.578 |
| glibc | Multifile hold/range/substitution | 72.946 (53.979–83.483) | 120.170 (94.960–150.696) | 0.607 |
| musl | Historical substitution | 66.975 (63.980–73.744) | 91.026 (87.923–94.015) | 0.736 |
| musl | Substitution/branch loop | 222.865 (203.190–234.436) | 182.627 (176.288–224.732) | 1.220 |
| musl | Multifile hold/range/substitution | 76.678 (69.931–82.457) | 75.934 (67.955–83.062) | 1.010 |

The glibc run has substantial timing spread. Musl's branch workload is slower
than GNU, and its multifile workload is approximately even in this run.
The original slower-than-GNU historical substitution result was not
reproduced. No speculative performance optimization was added, and no
before/after speedup is inferred from the separate historical runs.

Final `loadables/sed.c` SHA-256:
`cbb0ad6d7673b63669ad575750d430c6a10388d3db4e7f6516df26d6027234c0`.
The glibc binary SHA-256 is
`0ce393dfe426d3c935892c443f393ce6777622231ce88a3d2cb34124fdfb65a3`;
the native musl binary SHA-256 is
`dc0c3717c9a49ed0388556ccfec27b19c498ae1d5a71b9e78e51abbc20f82c82`.
Raw distributions and per-pass validation are retained in
`benchmark-v2-native.json` and `benchmark-v2-musl.json` in the correction
receipt. Earlier measurements and failed checks are retained separately.
No QEMU-to-native performance ratio is reported.

## Historical measurements before these corrections

Intel Core i7-9850H, Linux x86-64, CPU 11, GCC 14.2, Bash 5.3.15 and GNU sed
4.9. Each cell is milliseconds for eight calls: median followed by min–max
across seven samples. Every pass's bytes matched the independent oracle and
GNU; shell loops checked every invocation's status. Files were warm, PATH was
empty, LC_ALL was C, and output was a fresh regular file for each pass.

| Workload | Bytes per call | Builtin ms | GNU ms | Builtin / GNU |
|---|---:|---:|---:|---:|
| Historical substitution | 423,000 | 20.518 (19.618–21.828) | 67.282 (64.999–67.802) | 0.305 |
| Substitution/branch loop | 408,005 | 61.830 (58.274–64.873) | 122.043 (114.420–131.188) | 0.507 |
| Multifile hold/range/substitution | 176,010 | 24.427 (24.033–26.551) | 49.733 (47.605–54.844) | 0.491 |

The final binary SHA-256 is
`0cd4ffda506b9c5fb397ceeffd958f23cfc111ab53101d673d72ae4c28ba051e`;
`loadables/sed.c` SHA-256 is
`946e2fcfe2df380245019ef6941cccb80747e56962c0bf99dc36bf70f554e4d9`.
The historical text fixture retains SHA-256
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`.
Raw distributions, per-pass output hashes, options, operand hashes, versions,
build flags and affinity are in the task receipt's `bench-final.json`.

The rebuilt starting implementation also passed substitution and branch batch
validation. Its separate run measured 18.090/72.080 ms (builtin/GNU) for the
historical substitution and 61.642/146.632 ms for branching. Thus the historical
slower-than-GNU result was not reproduced in this calling pattern. No speculative
performance optimization was added. These are separate baseline/final batches,
not an interleaved before/after optimization experiment.

The final multifile oracle includes the final global line number, 16002, as
well as the transformed held content. It rejects the starting implementation;
no baseline builtin timing or speedup is reported for that case. The initial
concatenation-only experiment is retained separately and is not used to qualify
multifile cycle semantics. `bench-baseline-cycles.json` records the stronger
baseline oracle's rejection.

A 400-call gprofng run validated all 169,200,000 output bytes after separating
collector messages from command output. Its five CPU sample ticks are too few
for useful hotspot attribution; no optimization decision is based on them.
The earlier capture attempt and its failed validation are retained separately.
These regular-file measurements do not qualify pipe throughput, and the new
capture method cannot establish a speedup over historical `/dev/null` reports.
