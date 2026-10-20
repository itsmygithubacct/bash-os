# uclampset follow-up verification

This follow-up starts at `29fb981805c57e6d140011cde444ceb3ebac9f17`,
which contains the completed predecessor implementation and its effective-pair
preflight correction. The original 28-test suite is retained. This work adds
independent regressions, strengthens system mutation preflight and command
output handling, and remeasures the corrected implementation.

## Changes and policy boundary

PID setters continue to copy `sched_getattr` and use `KEEP_POLICY |
KEEP_PARAMS`, with only the requested clamp flags. `-R` resubmits the current
policy with `RESET_ON_FORK | KEEP_PARAMS`. Scheduler policy, nice, priority,
runtime, deadline and period remain outside the command's policy boundary.
Finite decimal values are `0..1024`, plus the CLI's explicit `-1` reset
sentinel. Invalid numbers, PIDs, operands and effective min/max pairs are
rejected before setters run. All thread requests are prepared before any
thread is changed. The existing ambiguous unsupported-kernel `0/0` handling
remains documented in [the predecessor report](opus-uclampset.md).

System setters now open every changed file **without truncation before the
first write**. `access(W_OK)` could succeed even when the later `open` failed
because of effective credentials, a mount or a security policy. A denied
second open previously allowed a temporary change to the first file. The
held descriptors now serve both updates and recovery, avoiding a second
pathname lookup. Writes are still ordered to keep min <= max throughout.
A failed or short write triggers attempted restoration of every attempted
file in reverse order, including the failing file. EINTR retries the complete
request; a short write is never retried as a separate numeric tail. Regular
fixture files have their stale suffix removed after a complete write; real
procfs sysctls have size zero and receive one complete write without truncation.
Close errors are reported and all opened descriptors are closed.

Command mode still uses literal argv in a child, including native builtins
under an empty PATH, and propagates normal exits, signals and lookup errors.
A failed verbose status read or output flush now stops the child before it
runs the command. The parent shell's clamps, variables, directory, signal
handler and background jobs remain intact. No common helper changed.

There is no transaction spanning threads or sysctls. Concurrent task or
credential changes can cause a later kernel refusal after an earlier thread
was changed. Recovery can itself fail; the diagnostic identifies the file.
A close error is reported after the write, and does not imply that the update
was undone. These are runtime failures, not successful rollback guarantees.

## Validation

`tests/sol-uclampset.py BINARY` runs the original suite plus seven follow-up
regressions. It compiles the command-specific syscall interposer, so it must
run through the build gate. `tests/sol-uclampset-sanitize.sh BINARY` runs the
same suite against an explicitly mapped ASan/UBSan loadable.

The new assertions cover:

- A verbose command's `/dev/full` error prevents an external marker command
  from running, while the parent remains usable.
- An injected permission denial on the second system-file open leaves both
  contents and modification timestamps unchanged, with no write attempted.
- Failed, zero-length and short second writes in both update orders restore
  both private files. The interposer records the production writes and their
  payloads, rather than only recording opens.
- EINTR, failed closes and descriptor cleanup; repeated PID/system setters
  and command invocations in one shell with a background job and SIGCHLD trap.
- A real reset-only PID update preserves every other scheduler parameter.
  Real command mode sets reset-on-fork in its child, and a subsequent fork
  clears that bit as expected. These real-kernel cases require no utilization
  clamp support and run independently of the emulation.

The two primary regressions are also run against a preserved baseline binary
and must fail there. The complete predecessor suite runs against that binary
using exact snapshots of its original test and interposer sources.

Successful utilization-clamp requests are checked through the genuine
production syscall path with interception. The shim uses real `sched_getattr`
for task existence and unrelated scheduler fields. System mutations use
private `BASHOS_PROC_ROOT` fixtures. This qualifies the software paths; it does
not qualify live host sysctl writes. The current kernel lacks
`CONFIG_UCLAMP_TASK`, so live PID clamp coverage verifies its real
`EOPNOTSUPP` refusal against an independent ctypes request. The suite's live
read/set/read branch remains available for a supported kernel. No host-wide
scheduler limits are changed during testing.

## Measurement method

`bench/sol-uclampset.py BINARY SHIM.so REPORT.json` compiles nothing and must
run through the bench gate. Query and refused-setter workloads have matched
util-linux references. Accepted PID setters and system fixture writes are
labeled syscall-shim timings, with no external ratio. Each sample uses the
same owned idle child, options and fixture reset rules. One warm-up precedes
nine samples on a fixed recorded CPU; order reverses each round.

Every repeated call records its exact exit status. Every query line and
refusal diagnostic is checked, every accepted PID request is compared with
independent scheduler fields and explicit expected clamp flags, and every
system write's payload, length and result are checked. The timer includes
the shell loop, redirections and status recording; checks occur after the
timer. The report includes distributions, fixture/output hashes, source,
binary, shim and harness hashes, versions, environment and work counts.
The unchanged shared query benchmark is also reproduced separately.

Validation completed with 28/28 predecessor tests, the two expected baseline
regression failures, 35/35 final normal tests and 35/35 ASan/UBSan tests. No
case was skipped. All compilation ran within the campaign build gate. The
final binary contains only the selected `uclampset` loadable and stock Bash
builtins; the build supplies its usual `_jsmn` helper. There are no required
companion loadables or changed common helpers.

Historical reports and shared catalog files are preserved. Raw benchmark
reports and per-sample outputs, statuses and syscall logs are stored in the
task evidence directory, separately for the preserved baseline and final
binary.

## Recorded results

All adapter samples validated: 300 calls per sample, one warm-up and nine
timed samples per implementation, CPU 11. The run used Bash 5.3.15, GCC 14.2,
glibc 2.41, util-linux 2.41.5 and Linux 6.12.111 on an Intel Core i7-9850H.
The adapter retained raw output, statuses and syscall logs for every sample.

| Workload | Baseline median ms/call | Final median (range) ms/call | Final util-linux ms/call | Final builtin/external |
|---|---:|---:|---:|---:|
| Owned-child query | 0.0485 | 0.0484 (0.0421–0.0510) | 0.8382 | 0.0578 |
| Refused PID setter | 0.0413 | 0.0400 (0.0364–0.0430) | 0.7795 | 0.0513 |
| Accepted PID setter, syscall shim | 0.1135 | 0.1197 (0.1086–0.1429) | — | — |
| Private system setter, intercepted writes | 0.1274 | 0.0853 (0.0797–0.0869) | — | — |

The unchanged shared `bench/loadables.py --only uclampset --passes 136`
case also validated all 136 passes, with seven timed samples: baseline
5.135 ms/batch versus util-linux 109.705; final 5.092 versus 101.814.
Both implementations have per-case status `ok`; BusyBox is unavailable for
this command. Its absence is not counted as a passing reference.

No query bottleneck was reproduced, and no query optimization was needed.
The system fixture result includes the changed file-handling work; it does
not establish a live sysctl speedup. Earlier historical measurements are
retained and are not paired comparisons with these builds.

Baseline binary SHA-256:
`917e61aea85cb274bd86e85313c31054d820caffcd98342902e8b811a2dd11b6`.
Final binary SHA-256:
`60e53bfd01403a1162d69ae04d2d15ce6d026ba4f34ede400e8be1051baedca2`.
Final `loadables/uclampset.c` SHA-256:
`8b52f8947f7ef1b7604aacd867908207dd7627dc9d7bcd1e6e769c890f0f5d03`.
The final report records the pre-commit working-tree source hash; the receipt
binds that exact hash to the delivered commit. Full distributions, versions,
fixture hashes and environment are in `baseline-controlled.json`,
`final-controlled.json`, `baseline-query.json` and `final-query.json` in the
task evidence directory.
