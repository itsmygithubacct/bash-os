# pr implementation and qualification

The command owns its option parser, record layout, page selection and buffered
I/O in `loadables/pr.c`. No common helper changes are required.

The original named layout exclusions in `tests/pr-parity.py` are now assertions.
`tests/sol-pr-cli.py` adds focused GNU byte comparisons for the added CLI and
formatting surfaces, invalid input, repeated standard-input operands and
persistent descriptor ownership. Both suites run with an empty `PATH`, fixed
C locale and UTC. Headers from operands use fixed modification timestamps.
The mixed-reader integration suite requires `head,sed,fold,expand,nl,tac,bc`
in addition to `pr`; these are validation companions rather than runtime
requirements of `pr`.

`bench/sol-pr.py` measures plain records and numbered three-column records with
TAB, NUL, CR and backspace. Each batch performs ten fresh input redirections in
one shell. A status marker follows each invocation; the entire batch must equal
ten independent GNU expected outputs and successful status markers. One warmup
and seven alternating-order samples use the same pinned CPU. Reports retain
fixture, source and binary hashes, options, work counts and environment.
These end-to-end wall times include shell startup and captured output delivery.
The existing `bench/loadables.py --only pr --passes 77 --runs 7` is also run
unchanged. Raw reports and command logs are kept with the task receipt, outside
historical datasets.

Validation results, measurements and remaining limits are recorded below after
qualification.

## Current qualification

The implementation remains **incomplete** for full GNU core behavior. The
original named exclusions are resolved: all 1,569 assertions in the expanded
original suite pass, with no layout skips. The focused CLI suite passes 214
checks, including the original 42 input-form-feed probes. Invalid options now
return GNU's failure status 1; the old status-2 assertions were strengthened
to query GNU directly.

A separate 294-case exploration of input form feeds found 47 differences.
Merged inputs can hold a column for too long, or print a form feed that GNU
suppresses when a natural page boundary already coincides with the input
break. Across-column layouts can also end a page where GNU continues the row.
For example, merging two files both containing `1\n2\n\f\n3\n4\n` with
`-t -l2 -m` emits an extra form feed before `3` here; GNU suppresses it.
These differences remain unsupported; the exploration exits nonzero and its
raw differences are retained with the task receipt, not counted as passes.
The regular suites do not skip or weaken any former hard case. Both command
suites also pass under AddressSanitizer and UndefinedBehaviorSanitizer; the
native mixed-reader suite passes 156 checks.

Balanced/across single-file column formatting still buffers the complete input
before rendering. Consequently it waits for EOF even when GNU can deliver a
full page earlier, and memory grows with the input. Single-column terminal
line delivery, bounded single-column page selection, repeated redirects,
shared descriptors, repeated `-` operands, descriptor-zero ownership and
failed-write recovery are covered by the focused checks. Input form-feed
interactions with repeated standard-input operands are not fully qualified.

No shared helper changed. GNU's translated diagnostic wording and unique
long-option abbreviations remain outside the documented CLI scope. No hardware
is involved; qualification is native Linux rather than a new cross-libc or
RISC-V run.

## Performance investigation

The first implementation passed correctness checks but regressed the repeated
plain case from 27.453 ms to 58.367 ms, and the control-byte column workload
measured 142.068 ms versus GNU's 127.944 ms. These are valid-output measurements,
retained separately from the final optimized reports. A gated `perf record`
attempt was rejected by the kernel's `perf_event_paranoid=3` policy; no profiler
samples or conclusions are claimed.

Source inspection identified per-record control-byte scans and ordinary rows
entering general column arithmetic. The final implementation caches control-byte
presence per 64 KiB read buffer, delivers ordinary single-column records through
a direct path, reuses character classification, and uses a division-free path
for the default eight-column tab stops. The focused suite adds eighteen cases
around the read-buffer boundary to qualify the cached state.

## Validated measurements

Median milliseconds per fixed batch, builtin / GNU; all phases used CPU 11,
one warmup and seven measured samples, GNU coreutils 9.7 and Bash 5.3.15.

| Work per sample | Baseline | First implementation | Optimized |
| --- | ---: | ---: | ---: |
| Legacy plain: 77 × 423,000 B | 27.453 / 412.961 | 58.367 / 473.083 | 37.904 / 461.455 |
| Captured plain: 10 × 480,000 B | 16.574 / 97.148 | 22.321 / 88.922 | 16.045 / 87.820 |
| Captured columns/control: 10 × 340,000 B | 106.583 / 129.712 | 142.068 / 127.944 | 125.476 / 131.822 |

The captured workloads validate every warmup and timed invocation's complete
output and successful status marker against GNU. The unchanged legacy harness
validates 77 repeated outputs before timing, then discards timed stdout while
checking statuses. Raw sample distributions, hashes, versions and environment
are retained in the reports. The baseline, first implementation and optimized
reports use `baseline`, `final` and `fast` filename suffixes respectively.

These phases are separate observations, not a paired speedup claim across
builds. The optimized captured plain case is close to its baseline; the legacy
plain case still costs more than the baseline. The control-byte case is close
to GNU. Kernel profiling was unavailable, so the remaining legacy-case cost has
not been attributed to measured function-level counters. Only valid-output,
within-phase GNU comparisons receive ratios. The full command remains incomplete
for the core pagination and streaming limits above.
