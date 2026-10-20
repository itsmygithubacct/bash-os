# sed cycle, regex and shared-input completion

Replacement text also decodes `\r`, `\a`, `\f`, and `\v` to their control
bytes, including with captures and case conversion. The focused suite retains
18 exact GNU comparisons for these and the existing newline/tab escapes.

The measurements below precede this replacement-escape correction. They remain
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
use their POSIX regex API: full GNU binary regex behavior is not qualified there.

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
Non-Linux pipes and terminal lookahead retain the stdio fallback limitation.

The command remains a subset of GNU sed. Existing `q` final-newline preservation,
`l` wrapping, auxiliary `R` framing and execution opt-in behavior are retained;
see [head/sed notes](head-sed.md). These fixes do not establish full GNU option,
exit-code, signal or cross-libc equivalence. Numeric overflow is rejected; GNU
saturates some out-of-range values instead.

## Validation

The focused build selects `sed,head,fold,expand,nl,pr,tac,bc`: sed needs no helper
or required companion; the others serve the existing input-lifetime integration
suite. Build commands, including sanitizer compilation, must use the campaign
build gate. Measurements must use its bench gate.

```
python3 "$CAMPAIGN_SCRIPTS/gated.py" build -- \
  ./build.sh --include sed,head,fold,expand,nl,pr,tac,bc --name sol-sed
python3 tests/sol-sed-parity.py out/bash-sol-sed
python3 tests/head-sed-parity.py out/bash-sol-sed
python3 tests/sed-streams.py out/bash-sol-sed
python3 tests/input-lifetime.py out/bash-sol-sed
python3 "$CAMPAIGN_SCRIPTS/gated.py" build -- \
  bash tests/head-sed-sanitize.sh out/bash-sol-sed
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
or full-profile build was run. Non-glibc GNU binary-regex parity remains open;
these results qualify the Linux/glibc implementation.

## Measurements

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
