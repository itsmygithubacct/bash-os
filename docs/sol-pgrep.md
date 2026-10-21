# pgrep regular expressions and process selection

The shared pgrep/pkill backend uses POSIX extended regular expressions, compiled
once per invocation. `-x` requires a whole-name or whole-command-line match,
including when the expression contains alternatives. Invalid expressions return
2 before opening procfs. `killall` continues to compare literal names; `killall5`
continues to select by session and omit lists. An explicit `BASHOS_PROC_ROOT`
remains read-only for signal operations.

The supported selectors are `-u/--euid`, `-U/--uid`, `-G/--group`,
`-P/--parent`, `-g/--pgroup`, and `-s/--session`. Each accepts up to 256 comma-separated
alternatives; different selectors must all match. User/group names are resolved
through the system account database. Zero session/process group means the
caller's session/process group. `-u` now selects effective UID, as procps does;
`-U` selects real UID. The separate killall `-u` behavior retains real UID.
Numeric overflow, malformed lists and malformed proc records are rejected or
skipped rather than wrapped into other identities.

For pgrep and pkill, `-n/--newest` and `-o/--oldest` select by start time; equal times use
highest/lowest PID respectively. These flags are mutually exclusive and cannot
be combined with `-v`. Listing, custom delimiters, count, inversion, short option
clusters and repeated invocations are covered. Command lines use a growable
buffer rather than truncating at 4095 bytes; embedded newlines become spaces,
as in procps. Listing output failures return 3; version output failures return
1 in all four shared-dispatch commands. In both cases a
later invocation can write successfully after its output descriptor is restored.

This is the documented selector surface, rather than a claim to implement every
procps option. Terminal, namespace, pidfile, cgroup, environment, thread and
run-state selectors are outside this task. Newest/oldest are exposed for pgrep and pkill. As before, empty command lines are skipped under `-f`, and name matching
reads `/proc/PID/comm`. Procfs is a changing snapshot: already-open files can
remain readable after the directory disappears, and unreadable records are
skipped.

`tests/sol-pgrep-check.py BINARY` executes the production builtin with an empty
PATH. Synthetic proc trees distinguish real/effective UID and real GID, parent,
group and session, with irregular stat names, long command lines, malformed and
missing records. FIFO synchronization removes a process entry during its read.
A persistent shell checks regex cleanup, changing selectors, descriptor counts
and recovery after `/dev/full`. Live parity uses only direct children created by
the test and restricts every pgrep/pkill query to their parent. Signal delivery
is checked with USR1 handlers. Literal killall names are unique to those owned
children; killall5 uses only read-only fixtures.

`tests/sol-pgrep-tools-build.sh OUTPUT_DIR` builds the read-only procps adapter and
an ASan/UBSan harness. It must run through the build gate. The harness includes
the entire production source with only the Bash ABI stubbed;
`tests/sol-pgrep-sanitize.py HARNESS` checks repeated dispatch and leak cleanup.

`bench/sol-pgrep.py --binary BINARY --shim OUTPUT_DIR/proc-shim.so --regex
--output REPORT` must run through the bench gate. It generates 512 fixed process
records and compares the builtin with unmodified procps pgrep. The adapter maps
absolute `/proc` paths to the same read-only fixture; it does not implement
matching. Each warm-up and measured pass has its complete output and status
checked against an independent arithmetic/fixture oracle. Seven alternating
samples, fixed affinity, all fixture/source/binary hashes, versions and sample
distributions are recorded. Timings include shell startup, external process
creation and captured output. The historical kthreadd selection is retained,
with a deterministic 512-entry fixture rather than the host process list.

Regex anchoring and selector meanings follow the [procps documentation](https://man7.org/linux/man-pages/man1/pgrep.1.html) and [upstream implementation](https://gitlab.com/procps-ng/procps/-/blob/master/src/pgrep.c).

The original implementation at `1a716f3` passed 101 native fixture, persistent-shell and owned-child
checks. ASan/UBSan passed 21 cases, each repeated 100 times with leak detection.
All five benchmark cases passed every warm-up and measured output/status check.
The raw receipts and reports are kept in the task evidence directory, rather
than replacing historical benchmark data.

On this native x86-64 run with procps-ng 4.0.4, CPU affinity was fixed to CPU 11.
Each cell below is the median of seven samples, with 34 calls per sample, after
one warm-up batch. All process-selection cases use the identical 512-entry
fixture (SHA-256 `7fcc59e9e5409f3b20322218bb00cda223acd9eb86a497ad6c78b4b765926130`).
These measurements precede the version-output error fix and do not measure the
corrected source. The measured binary SHA-256 is
`c0c792a4f1e01d1ffc21e889b89d45cded0fa257d69e6470ea668d8572427b55`.

| Case | Builtin ms | Procps ms | Builtin / procps |
|---|---:|---:|---:|
| `pgrep-kthreadd` | 71.979 | 616.914 | 0.117 |
| `pgrep-select-512` | 178.534 | 432.606 | 0.413 |
| `pgrep-cmdline-512` | 162.963 | 626.726 | 0.260 |
| `pgrep-oldest-512` | 134.948 | 401.644 | 0.336 |
| `pgrep-invalid-regex` | 1.683 | 37.928 | 0.044 |

The invalid-regex case measures 34 validations and does not scan process records.
The baseline exact-name case already performed well: 75.181 ms for the builtin
versus 658.689 ms for procps on the same fixture. No former slowdown was
reproduced, so no speculative performance optimization was introduced. The
regex and selector cases add validated workloads; the substring baseline cannot
supply valid results for those cases. These data are not paired with the
historical host-process-list timings.
