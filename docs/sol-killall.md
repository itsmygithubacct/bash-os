# killall: selection, safe delivery, and fixed-work measurements

`killall NAME [NAME ...]` selects exact Linux comm names and signals each matching
PID once. `-f` selects exact full command lines, with NUL-separated arguments
joined by spaces. `-u` filters the real UID, accepting a number or account name.
Signals accept names, optional `SIG` prefixes, or positive numbers below `NSIG`;
the default is TERM. `-e` and `--exact` are compatibility no-ops. The injected
shell command is `killall`; a dynamically loaded entry is named `bashkillall`.

The implementation now rejects PID, UID and signal overflow before narrowing
conversions, skips malformed UID tokens and embedded-NUL comm files, and avoids
claiming exact matches on truncated proc records. Previously, oversized fixture
PID directory names generated intercepted `kill(-1, SIGTERM)` requests. The test
shim never forwarded those requests. The killall wrapper now uses Bash's output
error check and passes arguments directly to the backend, without rewriting
Bash-owned word-list links to remove `--exact`.

`loadables/pgrep.c` is a shared backend. The integrated regex-selector backend
retains complete comm checks, canonical bounded PIDs and case-insensitive signal
prefixes. Full command lines use a reusable growable buffer for both exact and
regex selection. Only pkill accepts signal zero; killall requires a positive
signal. UID fixtures contain complete four-field Uid and Gid records, while
malformed-ID tests remain fail-closed. The build selection must explicitly
include **killall,pgrep**.

## Validation and signal safety

The task-owned Python driver executes the actual production command with an
empty PATH. A separately compiled preload shim redirects `/proc` reads into
private fixture directories and records signal requests. Fixture tests never
forward signals, including broad selections and malformed negative PID requests.
The production `BASHOS_PROC_ROOT` read-only signal guard remains in place and has
its own assertion; the shim supplies the otherwise unavailable mutation fixture.

Live tests create two uniquely named Python children. Before every real target,
the driver verifies the child handle is live, its kernel PPid is the driver,
its real UID is the test user's UID, and its comm is the expected unique name.
The shim independently repeats PID, PPid, UID and comm checks immediately before
forwarding an individual positive-PID syscall. Every delivered request is logged.
Handlers acknowledge USR1 and USR2; wait statuses verify STOP, CONT and default
TERM. The similar-name sibling remains alive. Cleanup verifies ownership again.
No host user/group broadcast is performed.

The suite covers exact versus prefix/suffix matches, multiple and repeated names,
`-f`, empty arguments and command lines, numeric/named real UID filters, named
and numbered signals, invalid options and numeric overflow, no matches, missing
proc files/root, malformed PID/UID/comm entries, truncated records, read-time
vanishing processes, ESRCH and EPERM delivery failures, and partial success.
Persistent-shell checks repeat selection and self-exclusion 250 times and compare
FD tables before and after. Count/version output failures use `/dev/full`,
including recovery in the same shell. Companion pgrep checks cover exact names
and both exact and substring long command-line handling.

Build the shell and shim through the campaign build gate, then run:

```sh
./build.sh --include killall,pgrep --name sol-killall --no-strip
cc -Wall -Wextra -Werror -O2 -fPIC -shared tests/sol-killall-shim.c -ldl -o "$BASHOS_TASK_DIR/sol-killall-shim.so"
python3 tests/sol-killall-check.py --binary out/bash-sol-killall \
  --shim "$BASHOS_TASK_DIR/sol-killall-shim.so" --report "$BASHOS_TASK_DIR/correctness.json"
```

`tests/sol-killall-sanitize-build.sh`, also run through the build gate, builds a
replacement from the same production sources with ASan/UBSan using the targeted
shell's generated headers. Run the driver with `--module` pointing to that
replacement, `SOL_KILLALL_ASAN` set to the path in `asan-runtime.txt`,
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`, and
`UBSAN_OPTIONS=halt_on_error=1`. This checks the changed C paths rather than
instrumenting the entire Bash interpreter; interpreter leak detection is disabled.

## Performance method and scope

Run `bench/sol-killall.py` through the campaign **bench gate**, with `--binary`,
`--shim`, and `--output`. It does not compile. It pins to the gate-selected CPU,
uses one warm-up and seven or more samples, and validates every invocation's
status plus every signal request against independently constructed expectations.
The raw report records all samples and distributions, exact fixture and source
hashes, binary/shim hashes, options, reset rules, work counts, compiler, shell,
Python, kernel and CPU information.

Selection-only cases scan 64 and 256 fixed comm files for an absent exact name.
Matching cases scan the identical trees and intercept 8 and 32 deliveries per
pass. Each sample performs 100 passes in one shell. A separate single-entry
fixture selects one verified owned child for 100 SIGCONT deliveries. The shim
records time immediately around the actual `SYS_kill` call, excluding proc
selection, ownership checks and log writes; its batch wall time includes those
costs. SIGCONT leaves the child running, verified after every batch. Timing
includes clock-read overhead and scheduling effects. These are fixture and
syscall-shim timings; there is no external ratio or claimed optimization speedup.

This is the documented software scope, not full psmisc compatibility. `-f` is an
extension with exact joined-line matching; regex, wait/age filters and process
group broadcasting are not provided. Command-line matching reads the complete
record into an input-sized allocation; allocation or read failures skip the
entry. Tests reject a truncated prefix and require a full 5000-byte exact match.
Delivery tolerates
exit/read races, but selection followed by `kill` does not pin process identity
with pidfds and cannot eliminate the general PID-reuse race. There is no hardware
qualification requirement.

## Original standalone results

The measurements below describe the original standalone source and binary.
They have not been rerun for the integrated regex-selector backend.

The baseline build passed 36/51 cases. The final native build and the replacement
ASan/UBSan module each passed 51/51. The baseline's 15 failures remain in separate
raw reports, including the intercepted negative-PID requests. No old assertions
were removed or weakened. The final native binary is Bash 5.3.15, GCC 14.2.0,
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, unstripped, SHA-256
`83e099f77d2901d028aadf12ea61ec1499b49b4230b8ca6f23a9df5577d8fec9`.

All five workloads passed every repeated status/delivery assertion after a
warm-up, with seven samples each, on CPU 11. Host: Linux-6.12.111+deb13-amd64-x86_64-with-glibc2.41;
Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz. Times include shell startup, loop and status output.

| workload (100 passes) | median ms | min–max ms |
|---|---:|---:|
| selection-only-64 | 29.490 | 27.469–35.048 |
| selection-intercepted-delivery-64 | 30.896 | 30.030–33.595 |
| selection-only-256 | 99.214 | 95.053–157.421 |
| selection-intercepted-delivery-256 | 124.639 | 114.680–135.123 |
| controlled-delivery-one-owned-child | 10.116 | 9.131–10.469 |
| actual SIGCONT syscall time only, 100 deliveries | 0.111252 | 0.103881–0.113476 |

The 256-entry scan has a wide range; these are observed samples under campaign
host activity, not isolated maximum-throughput figures. The controlled syscall
median corresponds to approximately 1.11 microseconds per SIGCONT delivery;
selection and safety instrumentation are excluded from that syscall-only column.
These are new validated measurements, with no previous valid measured case and
no asserted bottleneck or speedup. No speculative performance rewrite was made.
Raw correctness, sanitizer, compiler, provenance and benchmark reports remain in
the task evidence directory; historical reports and shared catalogs are intact.
