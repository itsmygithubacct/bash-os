# renice: absolute priorities, safe verification and timing

`renice [-n] PRIORITY [-p|-g|-u] ID...` sets an absolute niceness.
`-n 16` sets 16 even when `POSIXLY_CORRECT` is set; it does not add 16.
This follows the traditional absolute interface, rather than the POSIX relative
`-n` interface. Successful calls are silent. PID selection is the default;
selectors change the interpretation of subsequent operands. Selectors before
the priority remain supported for compatibility.

The priority must be a complete decimal signed `int`, with no surrounding
whitespace. Linux clamps accepted values to -20 through 19. PID and group IDs
are decimal integers from 0 through `INT_MAX`. Numeric user IDs must fit `id_t`
without using its all-ones sentinel; other names are resolved with `getpwnam`.
Target zero has the kernel meaning: caller, caller's process group, or caller's
real UID, respectively. Lowering niceness requires sufficient privilege or
`RLIMIT_NICE`; negative requests can fail even for an owned process.

The implementation now consumes the priority once and rejects misplaced or
repeated `-n` before any mutation. Previously a late `-n` could change the
priority halfway through a list and expose its operand as a target. It also
rejects leading whitespace in numeric priorities and process IDs, and reports
failure (1) for invalid target operands even when none reach the syscall.
Missing priority/targets and malformed priority syntax return usage (2).
Target resolution and syscall failures continue to later operands and return
failure; successful earlier targets remain changed.

## Focused checks

Build only `renice` with `./build.sh --include renice --name sol-renice`.
There are no companion commands, libraries or command-specific shared helpers.
The normal build resolver includes its default `_jsmn` helper.
Run compilations through the build gate required by the surrounding campaign.

```
bash tests/sol-renice-build.sh /tmp/renice-fixtures
python3 tests/sol-renice-check.py out/bash-sol-renice /tmp/renice-fixtures/fixture.so
```

The test driver never compiles. The shared fixture intercepts the real
production `setpriority` call and supplies deterministic username resolution;
it never forwards a mutation to the kernel. It checks PID/group/user selector
transitions, zero IDs, UID limits, signed-int priorities, malformed and
overflowing arguments, missing operands, misplaced `-n`, partial `ESRCH` and
permission failures, repeated calls, descriptor counts and closed output.

Real kernel changes are confined to disposable owned children and a private
session containing two owned processes. Python `os.getpriority` and `/proc`
independently verify priorities. Tests check absolute repeated `-n`, upper
clamping, continuation after an invalid operand, actual denied negative
niceness, and unchanged parent priorities. The real denial test requires
`RLIMIT_NICE=0` and no effective `CAP_SYS_NICE`; it fails rather than silently
skipping in a privileged environment. All-user mutation is fixture-only.

The same suite can load an ASan/UBSan-instrumented production module using
`SOL_RENICE_MODULE`, `SOL_RENICE_ASAN_RUNTIME`,
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

The focused suite passed all 14 tests both natively and with ASan/UBSan.
Both unchanged legacy renice tests also passed, with no skips or sanitizer
findings. The legacy `tests/process-numeric.py` renice assertions remain intact.
The broad `tests/util-linux-smoke.sh` was inspected but is unsuitable for this
focused run: its renice case changes the caller's priority. Replace that case
with the owned-child tests during integrated test registration.

## Controlled measurement

Run the following through the campaign bench gate after the build:

```
python3 bench/sol-renice.py --binary out/bash-sol-renice --runs 7 --passes 1000 --output REPORT.json
```

The builtin and external util-linux command run in the same Bash binary,
with empty `PATH`, C locale, and no `POSIXLY_CORRECT`. Both use `19 -p PID`
and redirect command stdout to `/dev/null`. Every batch gets a fresh owned
child initially at nice 10. Every one of 1,000 sets checks its exit status and
independently reads `/proc/PID/stat`, requiring nice 19; Python also checks the
child with `getpriority` before and after. Both shell and Python parent
priorities must remain unchanged. No priority restoration or user-wide
mutation is attempted.

One warm-up per implementation precedes seven samples, alternating execution
order, pinned to a single recorded CPU. Timing includes shell startup and the
same validation loop for both implementations. The report retains every
sample, output/status checks, work counts, reset rules, environment, versions,
source and binary hashes, and the fixture-script hash. This measures repeated
absolute sets plus validation; it does not isolate syscall latency or measure
negative-priority/user-wide operation throughput. There was no historical
matched renice measurement or demonstrated internal bottleneck, so this work
does not claim an optimization over the earlier source.

The validated run used CPU 11 on an Intel Core i7-9850H, Linux 6.12.111,
Bash 5.3.15 and util-linux renice 2.41.5. Each row contains seven measured
batches of 1,000 sets and 1,000 priority reads, after one warm-up batch.

| Implementation | Minimum ms | Median ms | Maximum ms |
|---|---:|---:|---:|
| Builtin | 158.92 | 220.56 | 269.38 |
| External util-linux | 836.49 | 1,064.52 | 1,233.59 |

The external/builtin median ratio is 4.83. All 16,000 sets, including warm-ups,
passed status and independent priority checks. This shared-host result includes
the common shell validation overhead and the external command's invocation,
priority queries and discarded status output. It describes these complete
command loops, not isolated syscall latency. Raw distributions and provenance
are retained with the task evidence rather than merged into historical data.
