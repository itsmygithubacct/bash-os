# renice: util-linux 2.41.5

`renice` follows util-linux 2.41.5. The first argument is the priority.
`-n`, `--priority`, and `--relative` are recognized only when they are that
first argument. Later arguments are process IDs unless `-p`/`--pid`,
`-g`/`--pgrp`, or `-u`/`--user` changes the meaning of the IDs that follow.
A selector before the priority is not a selector: it is parsed as the
priority and rejected.

A bare priority is absolute. `--priority` is always absolute. `--relative`
is always added to the current priority. `-n` is absolute unless
`POSIXLY_CORRECT` is set in the environment, in which case it is added to
the current priority. The addition uses 32-bit wrap. Priorities and IDs are
base-10 `strtol` values kept as the low 32 bits of that result. `ERANGE` is
ignored. Leading whitespace and a leading sign are accepted. Trailing junk
rejects the token. An empty priority string is priority 0.

On success each target prints one stdout line and returns 0 when every
target succeeded:

```
ID (process ID) old priority OLD, new priority NEW
```

The label is `process ID`, `process group ID`, or `user ID`. `OLD` is what
`getpriority` returned before the change, which for a group or user is the
highest priority in that set. `NEW` is `getpriority` after `setpriority`, so
it is the value the kernel kept. Linux clamps the requested niceness to -20
through 19. A username is printed as its numeric uid.

`getpriority` failure does not call `setpriority`. `setpriority` failure,
including `EPERM` when an unprivileged caller tries to lower niceness, leaves
that target unchanged. A bad process or group id is `renice: bad KIND value:
TEXT`, where KIND is `process ID` or `process group ID`. An unknown user is
`renice: unknown user TEXT`. Later IDs are still attempted. The status is 1
if any ID failed.

A missing priority or target, or a priority with trailing junk, stops before
any change and returns 1:

```
renice: not enough arguments
Try 'renice --help' for more information.
```

```
renice: invalid priority 'TEXT'
Try 'renice --help' for more information.
```

`-n` after the priority is an ID, not an option. Earlier IDs in that command
are still changed. A user operand is looked up with `getpwnam` and, if that
fails, parsed as a number. A uid that does not fit a non-negative 32-bit int
is an unknown user. The end pointer is not cleared when a name lookup
succeeds, so a later name can be rejected when an earlier numeric parse left
trailing junk there.

ID 0 has the kernel meaning. `-g 0` and `-u 0` run in the shell and affect
the caller's process group or real uid. In a non-interactive shell that is
the same group and user an external renice would change. `-p 0` is applied
in a short-lived child, so the shell's own niceness stays unchanged, matching
an external renice that changes only itself. The printed id is still 0.

Exactly one argument of `-h` or `--help` prints the util-linux help text on
stdout and returns 0. Exactly one argument of `-v`, `-V`, or `--version`
prints `renice from util-linux 2.41.5`. Diagnostics use the `renice:` prefix
and `strerror` text. A stdout write error other than `EPIPE` is reported as
`renice: write error` and returns 1. `EPIPE` on stdout does not.

Lowering niceness requires privilege or a sufficient `RLIMIT_NICE`. Raising
niceness of an owned process does not.

## Qualification

Five comparisons stay oracle-compared against util-linux on the same owned
children. Their scripts and expected markers are unchanged:

- `migration-renice-owned-absolute`
- `migration-renice-owned-short`
- `migration-renice-owned-posix-relative`
- `migration-renice-selectors-users-zero`
- `migration-renice-target-failures`

The loadable-parity cases for a missing invocation, a malformed priority, a
malformed pid, and an unknown user also stay oracle-compared. `help -d`
reports the first documentation line, `Alter the priority of running processes.`

## Earlier interface

The previous builtin was silent on success, treated `-n` as absolute even
when `POSIXLY_CORRECT` was set, accepted a selector before the priority,
rejected a later `-n` before any change, and used status 2 for usage errors.
`tests/sol-renice-check.py` locks that earlier interface. It is not a check
of this contract. The measurement below is for that earlier builtin.

## Historical measurement

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
The numbers describe the previous silent builtin, not a new measurement of
the util-linux-compatible output path.
