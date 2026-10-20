# nl completion checks

`nl` uses the host BRE engine with `REG_STARTEND` when available. Other
platforms use a private, length-aware engine in `loadables/common/nl-regex.h`.
Both paths receive the record length without its trailing newline, reject
lengths which cannot fit a regex offset, and report matcher errors rather
than treating them as a nonmatch. An embedded NUL is data: anchors still refer
to the complete record, and negated classes and backreferences can span it.
GNU's dot behavior is preserved: `.` excludes NUL.

The fallback is an amalgamation of `src/regex/{tre.h,tre-mem.c,regcomp.c,regexec.c}`
and the public regex types from musl commit
`b1efda5b91735e33635376ca11c9b497a1c66e39`. The upstream sources are available
from [musl's repository](https://git.musl-libc.org/cgit/musl/tree/src/regex?id=b1efda5b91735e33635376ca11c9b497a1c66e39).
Their BSD license notices are retained in the header, along with musl's MIT
license. The implementation is private to `nl`, requires no companion
loadable or link library, and exports no regex symbols.

Local changes add explicit input bounds, distinguish end of input from NUL,
use bounded `memcmp` for backreferences, restore character state when backtracking,
try later start positions after a failed match, preserve byte values in
single-byte locales, distinguish invalid multibyte bytes from end of input,
and exclude NUL from dot. Word boundaries depend on the actual adjacent
characters, including at the ends of NUL-containing captures.
Types and entry points are renamed; helper functions have internal linkage.
`tests/sol-nl-amalgamate.py UPSTREAM_DIRECTORY OUTPUT_HEADER` reproduces the
header from six hash-checked upstream inputs without network access.
This avoids relying on libc regex internals or substituting another byte for
NUL, which could change bracket and backreference matching.

`--help=value` and `--version=value` now fail like other argument-free long
options. Help and version output also report write failures using the same
buffer as numbered output. Existing numeric, logical-page and invocation-state
behavior is retained.

Validation commands (builds must use the campaign build gate):

```sh
./build.sh --include nl,head,sed,cat,wc,tac,fold,expand,pr,bc --name sol-nl
python3 tests/nl-parity.py out/bash-sol-nl
python3 tests/sol-nl-check.py out/bash-sol-nl
python3 tests/input-lifetime.py out/bash-sol-nl
tests/sol-nl-build-modules.sh /tmp/nl-modules
NL_MODULE=/tmp/nl-modules/nl-fallback-plain.so python3 tests/nl-parity.py out/bash-sol-nl
NL_MODULE=/tmp/nl-modules/nl-fallback-plain.so python3 tests/sol-nl-check.py out/bash-sol-nl
```

`BNL_NO_STARTEND=1` forces the production fallback even on glibc, so its
binary matching and descriptor paths can be checked by the same suites.
The module builder also produces ASan/UBSan variants; preload the compiler's
`libasan.so` only into the Bash subprocess, as in `tests/nl-sanitize.sh`.
The existing `NL_REFERENCE` and `-l 0` adaptation assertions remain intact.

The focused suite adds explicit binary output oracles; GNU byte comparisons
for anchored BREs, classes, repetitions and backreferences, including 48
compound patterns over all 121 subjects of up to four bytes drawn from
`a`, `b` and NUL; C and UTF-8 character and invalid-byte cases; logical pages with
adjacent and repeated delimiters, blank groups and extreme counters; long
records and input buffer edges; option replacement and errors; chunked pipes
and named FIFOs; and 100 failure/recovery cycles with stable descriptors.
All builtin calls run with an empty PATH. The existing suite retains BusyBox
comparisons on its shared subset and terminal streaming checks.

Coverage is scoped to these contracts rather than every libc regex extension,
collating element or locale. BusyBox has no logical pages and truncates binary
records, so it is not an oracle for those cases. Native and forced fallback
checks do not by themselves qualify an entire cross-compiled shell.

The task-owned benchmark `bench/sol-nl.py` checks every pass's stdout and status
against independent Python byte oracles. It uses 48 invocations in one shell,
fresh input/output redirections per invocation, one warm-up and seven samples,
and alternating builtin/GNU order. It records pinned affinity, versions,
fixture/source/binary hashes, distributions and work counts. The successful
cases are `-ba` over the shared 423,000-byte text fixture and an anchored BRE
with a backreference over 16,000 records. Invalid regex and `/dev/full` failure
paths are measured separately with their expected empty stdout and exit 1.
Failure-path timings are individual self measurements without an external
ratio, because implementations can stop after different amounts of input.
Timings include shell startup, per-pass capture files and status recording;
these are batch measurements, not isolated matcher throughput.

Raw reports are kept in task evidence. Earlier reports and the measurements in
`docs/nl.md` remain separate and are not overwritten.

## Validated measurement, 2026-10-19

Intel Core i7-9850H, CPU 11; Linux 6.12.111, glibc 2.41, GCC 14.2,
Bash 5.3.15 and GNU nl 9.7. Each row is 48 invocations per sample, seven
samples after one warm-up. Every one of the 384 outputs and statuses per
implementation and case was checked against the independent byte oracle.
The complete distributions, hashes and versions are in the separate task
reports `focused-before-v4.json`, `focused-after-v4.json` and
`focused-fallback-v4.json`. Times include capture files and status recording.

| implementation | workload | builtin median [min–max], ms | GNU median, ms | builtin/GNU |
|---|---|---:|---:|---:|
| Baseline native | -ba | 65.17 [61.86–68.13] | 141.17 | 0.462 |
| Baseline native | BRE/backreference | 2197.02 [2042.75–2248.21] | 2425.15 | 0.906 |
| Final native | -ba | 67.19 [61.38–82.01] | 149.57 | 0.449 |
| Final native | BRE/backreference | 2247.08 [2169.33–2353.21] | 2335.73 | 0.962 |
| Forced fallback module | -ba | 74.32 [64.73–84.85] | 150.36 | 0.494 |
| Forced fallback module | BRE/backreference | 692.77 [669.80–743.53] | 2349.27 | 0.295 |

Native before/after ranges overlap; this work makes no native optimization
claim. The earlier `-ba` advantage remains, and the regex-heavy native case
is close to GNU. The fallback row is a forced production engine loaded as
an `-O2` shared object on this native host; it does not measure a musl shell.
There is no timing comparison against the original NUL-truncating fallback.

Failure paths use self measurements because implementations can stop after
different amounts of input. Both paths return the expected status 1 and empty
stdout on every pass, and a subsequent invocation succeeds in the tests.

| implementation | invalid BRE median, ms | `/dev/full` median, ms |
|---|---:|---:|
| Baseline native | 7.76 | 16.46 |
| Final native | 7.99 | 14.54 |
| Forced fallback module | 7.47 | 15.17 |

The unchanged shared harness also reproduced the earlier `nl -ba` workload:
48 passes, seven samples, with builtin/GNU/BusyBox statuses all `ok`. Its
median builtin/GNU times were 53.451/133.217 ms before and 53.760/123.843 ms
after. Those raw reports retain the shared harness's validation method; the
task adapter above checks the same text fixture and options on every timed
pass. Existing historical datasets and the earlier table in `docs/nl.md`
remain unchanged. The initial task adapter report is retained separately as
superseded: its error-path ratio fields are excluded from evidence, and the
current reports correctly label those cases as self measurements.

Final correctness validation passed all 1,556 existing and 191 focused checks
on native and forced-fallback paths, including ASan/UBSan variants, plus 156
mixed-reader lifetime checks. The existing `NL_REFERENCE` rejection adaptation
was exercised on both paths with a contract shim around GNU 9.7; this is not
an actual GNU 9.4 run.
