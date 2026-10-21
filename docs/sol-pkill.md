# pkill signal delivery

`pkill` uses the production pgrep walker for POSIX extended regular expressions,
whole-name or whole-command-line matching (`-x`, `-f`), and effective UID, real
UID, real GID, parent, process group and session selectors. Alternatives within
a selector are ORed; different selectors are ANDed. It excludes its own PID.
An explicit `BASHOS_PROC_ROOT` remains read-only for signal operations.
A pattern or one of `-u/-U/-G/-P/-g/-s` is required; `-n` or `-o` alone
is a usage error.

Conventional signal names such as `-TERM` and `-USR1`, case-insensitive `SIG`
prefixes, numeric signals and signal zero are supported. Default delivery is
TERM. Whole signal names take precedence
over selectors and grouped short options, including `-USR1`, `-URG`, `-PIPE`
and `-PWR`. Grouped `-cfx` and selectors after flags (`-cfP77`, `-cfu USER`)
use the same validation as separate options. Pgrep-only listing and inversion
options remain errors in pkill.

`-n/--newest` and `-o/--oldest` choose one matching process by start time,
breaking equal-time ties by highest/lowest PID respectively. These options are
mutually exclusive. Only the chosen PID is signalled; a failed delivery does not
fall back to another candidate.

Invalid arguments and invalid regular expressions return 2 before any signal
request. A successful request contributes one to `-c`; failed requests do not.
Status is 0 when at least one request succeeds, 1 when none succeeds, and 3 on
a fatal proc-open or output error. ESRCH races are silent; other delivery errors
are diagnosed. A failed request does not prevent attempts on later selected
processes. Count output can fail after delivery; status 3 does not undo those
signals, and callers should not assume it is safe to retry a mutating command.

`tests/sol-pkill-build.sh OUTPUT_DIR [BUILD_NAME]` builds the native binary,
fail-closed syscall adapter and ASan/UBSan harness. It must run through the
campaign build gate. Pkill requires pgrep through `config/helpers.json`;
killall and killall5 are included to check shared-backend regressions.

`tests/sol-pkill-check.py --binary BINARY --shim OUTPUT_DIR/pkill-intercept.so`
checks exact PID/signal requests against independent fixture arithmetic.
The adapter redirects `/proc` reads and intercepts `kill()` without a path to
the real syscall. It does not replace selection or matching code. Fixtures
use synthetic PIDs above the host's checked kernel PID limit, preventing
accidental collisions with the calling shell's self-exclusion.
They exercise regexes, selectors, signals, invalid input, missing/malformed records,
long command lines and injected delivery failures. Persistent-shell checks use
empty PATH, compare open descriptors, verify self-exclusion and recover from
closed stdout and `/dev/full`. The sanitizer variant is
`--binary OUTPUT_DIR/pkill-sanitize --sanitizer`; it includes the actual pgrep
source and pkill entry point, with only Bash ABI and syscall boundaries adapted.

Live checks create direct child processes with unique names and signal handlers.
Every query also restricts the parent PID to the test process. Selected children
acknowledge named and numeric signals; nonmatches remain alive and receive no
acknowledgement. Default TERM is checked through child exit statuses.
Cleanup addresses only those owned child PIDs.

`bench/sol-pkill.py --binary BINARY --shim OUTPUT_DIR/pkill-intercept.so
--output REPORT` must run through the bench gate. It scans a fixed 512-process
fixture and checks every output, exit status, PID, signal and delivered count
against an independent oracle. Each workload has one warm-up and at least seven
samples on a recorded CPU. The log resets before each batch; the fixture never
changes. Source, binary, shim and fixture hashes, options, work counts and
versions are stored with raw distributions. These are syscall-shim timings
including synchronous request logging, not kernel-delivery throughput or an
external speedup comparison.

The supported software scope does not include every procps option: terminal,
namespace, pidfile, cgroup, environment, thread,
run-state, `--signal`, real-time signal names and queued-signal options are
outside this implementation. Real-time signals can be specified numerically. UID/GID
permission errors are injected rather than requiring privileged account changes.
The walker reads a changing procfs snapshot and uses `kill(pid, sig)`; it cannot
eliminate PID reuse between reading a process record and delivery.

The corrected native x86-64 build passed 127 pkill cases, including real signal
acknowledgements and TERM exit statuses for owned children. ASan/UBSan passed
113 fixture cases, each repeated 25 times with leak detection. The existing
pgrep suite passed 101 cases, its sanitizer suite passed 21 cases repeated
100 times, and all 16 shared version-output failure/recovery cases passed.

The unchanged starting binary passed the existing 101 pgrep and 16 version
checks. New tests separately reproduced its rejection of grouped flags,
rejection of newest selection, and silent EINVAL delivery failures. The same
three tests passed against the corrected binary. Raw build, regression,
correctness and sanitizer logs remain in the task evidence directory.

All four benchmark cases passed every warm-up and measured output, status,
PID, signal and count check. Each row below is one batch of 34 invocations,
with seven samples after one warm-up batch, pinned to CPU 11 on an Intel
Core i7-9850H running Linux 6.12.111. Selection workloads scan 512 fixed records
per invocation; invalid regex validation scans none.

| Workload | Median ms | Min–max ms | Intercepted deliveries per batch |
|---|---:|---:|---:|
| Regex and combined selectors | 288.900 | 267.765–301.222 | 1,156 |
| Full command line and parent selector | 304.046 | 289.745–312.458 | 17,408 |
| Newest matching process | 187.064 | 169.511–215.287 | 34 |
| Invalid regex | 2.536 | 2.152–4.026 | 0 |

The measured binary SHA-256 is
`8a86ded3735c9e32423e4652d0116242e9d1b49b7a711477811064e617406b11`.
The fixture SHA-256 is
`e907bbc76e180eb44c9a5d5820c6f2e832c17bc59a1aabfe93c7ace3cf10e0dd`.
The raw report retains all samples, source and adapter hashes, versions and
environment details. There was no existing pkill timing to reproduce; these
establish measured workloads without a speedup claim. Synchronous signal-log
writes are included, so the figures do not estimate real kernel signal cost.

Integration qualification: `-c` retains the existing count of successful delivery requests, which differs from procps matched-process counts when delivery fails. The supported option subset also excludes `-e/--echo`, `-i/--ignore-case`, `-A/--ignore-ancestors`, `-H/--require-handler`, and `-q/--queue`. Newest/oldest (`-n`/`-o`) selection now applies to pkill as well as pgrep.
