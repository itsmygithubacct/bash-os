# netstat completion work

`netstat` uses the `ss` transport, proc readers, rendering and process map.
Build it with both companions:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include netstat,ss --name sol-netstat
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  bash tests/sol-netstat-build-fixtures.sh "$EVIDENCE"
python3 tests/sol-netstat-behavior.py --binary out/bash-sol-netstat \
  --shim "$EVIDENCE/shim.so" --output "$EVIDENCE/correctness.json"
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-netstat.py --binary out/bash-sol-netstat \
  --shim "$EVIDENCE/shim.so" --output "$EVIDENCE/benchmark.json"
```

The product change is limited to `loadables/netstat.c`: flush stdout before
returning, propagate output failures, and clear a previous call's stdio error
indicator at entry. This includes `--version`. A failed write must return failure
while allowing another invocation in the same shell to succeed.

The scope is the documented numeric TCP/UDP/Unix subset, including short and
long aliases. It does not claim complete net-tools compatibility, service-name
resolution, routing/interface tables or IPv4/IPv6 selection options. Unix queue fields
are currently fixed at zero; queued Unix traffic accounting is outside this
software-path fixture scope. The current
shared renderer uses ss state labels (`ESTAB`, `UNCONN`) and ss process
annotations even under the legacy `PID/Program` header.

## Independent fixtures

The correctness script creates its own IPv4/IPv6 loopback TCP listeners and
connections, bound and connected UDP sockets, and private pathname Unix
listeners/connections. Host output is selected only by exact owned endpoint
pairs and the creator's PID/FD. Other host records never establish coverage or
become expected output. TCP listen backlog and empty queues are asserted. `--live-only` runs these
checks without a shim; `--no-live` confines a run to deterministic fixtures.

The preload shim supplies independently encoded netlink messages and proc
files to the actual production implementation. It changes system-call inputs;
it does not replace any decoder, option parser, filter, process mapper or
renderer. Its netlink transport checks request type, length and dump flags,
patches reply sequences, and honors the requested state mask. Its private proc
fixture contains known inode-to-PID/FD mappings and an injected EACCES directory.
Malformed messages, short payloads, mismatched sequences, malformed proc rows,
partial dump errors, denied tables, repeated calls and FD cleanup have separate
assertions. Every case gets a pass/fail result; the harness exits nonzero if any
case fails.

The ASan/UBSan build compiles the same source pair into a shared loadable and
loads its `bashnetstat` entry into the selected Bash. A shell function supplies
the public `netstat` name. Set `BASH_ENV` to the generated `sanitize-env.sh`,
preload the recorded ASan runtime, set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`
and `UBSAN_OPTIONS=halt_on_error=1`, then run the same Python suite. Bash's own
lifetime allocations are outside this targeted sanitizer scope; production
transport FDs are checked separately in the persistent shell.

## Measurement method

The benchmark has an independent complete-output oracle for a seven-record
netlink snapshot (TCP, TCP6, UDP and Unix), the same snapshot with three
private inode/PID/FD mappings, and a 10,000-record connected IPv4
proc table. The large table selects exactly those 10,000 rows, with no host rows,
no endpoint wildcards and no unverified count-only acceptance. Each batch uses
ten invocations in one shell with an empty PATH. Every invocation must succeed;
the entire repeated output is compared byte for byte after each batch.

One validated warmup precedes seven samples. The report records the fixed CPU
affinity, fixture hashes, exact options, reset rules, compiler/Bash/Python/kernel
versions, source and binary hashes, output hashes, work counts and all samples.
These are syscall-fixture wall times including shell startup and captured
output. There is no external ratio, live-host throughput claim or speedup claim.
Failed correctness cases are not benchmarked.

## Shared backend integration

`loadables/ss.c` is owned by the `sol-ss` task and is intentionally untouched
here. The evidence directory includes `backend-coordination.json`. Integration
must apply and verify the ss backend changes before treating netstat as
complete. In particular, unify endpoint formatting across transports, map proc
Unix states and listen flags, use UDP's unconnected state for `-l`, reject
malformed rows and short messages, propagate unavailable-table failures, and
avoid appending duplicate fallback rows after partial netlink output.

Register the new task-owned test separately during integration. Do not infer
completion from a harness's exit status without inspecting all JSON cases.

## Verified result

The targeted `netstat,ss` binary built successfully. The native suite passed
36 of 63 cases; the instrumented fixture suite passed 31 of 57 cases with no
ASan/UBSan diagnostic. Both suites exited 1 because the semantic failures are
retained. The six owned live cases passed five, failing UDP `--listening`.
The isolated build includes only the two required commands.

The starting netstat source, loaded against the same shared backend, returned
`0 0` for a table write and a version write redirected to `/dev/full`. The
replacement returns `1 1`, and the next invocation succeeds. Persistent-shell
FD sets were unchanged after 100 `-anp` calls through each fixture transport.
An initial live setup attempt exceeded the Unix pathname limit under a long
inherited temporary directory; the committed runner uses a private directory
under `/tmp` and executes every owned socket case.

The remaining failures belong to the shared backend:

- UDP listening requests use the TCP listen mask in both transports.
- Proc zero-port and IPv6 endpoints differ from netlink endpoints.
- Proc Unix rows use TCP state decoding and ignore listening flags.
- Invalid proc addresses and short netlink messages are accepted.
- Interrupted dumps and error payloads in `NLMSG_DONE` are ignored.
- A partial failed dump appends proc rows after already rendered rows.
- Unavailable netlink plus denied proc tables returns success with a header.

Consequently this task remains **incomplete** pending `sol-ss` integration.
No `ss.c` edit or backend fix is claimed by this commit. The native JSON has
27 failed assertions, including aliases and combined-family checks affected by
these defects; those are not 27 independent implementation defects. Existing
assertions were retained and expected output was not weakened to accommodate
the failures.

## Validated fixture timings

Measured on 2026-10-19, x86_64 Linux 6.12.111+deb13-amd64, Bash 5.3.15(1)-release, GCC 14.2, pinned to CPU 11. Each value is the wall time of ten calls in one shell, including startup and captured output. One warmup precedes seven validated samples.

| Work per call | Options | Median batch ms | Min–max ms |
|---|---|---:|---:|
| 7 snapshot records | `-an` | 1.407 | 1.319–1.527 |
| 7 snapshot records, 3 ownership mappings | `-anp` | 1.598 | 1.541–1.876 |
| 10,000 connected IPv4 records | `-tan` | 502.036 | 480.611–561.799 |

The raw `benchmark.json` in the evidence directory contains all samples and hashes. The measured binary SHA-256 is `aff7091d66ec52f3046cb3138f60ce29c45183d500dc16b5dfcb54872501b033`. Its source provenance is the starting HEAD plus the exact recorded working-file hashes; those hashes must match any commit to which the results are attributed. All three cases have status `pass`.

These successful subset timings do not clear the 27 native behavioral failures. There is no external netstat executable on this host and no external speed ratio. Other host activity can remain despite the campaign resource gate. No performance optimization or speedup is claimed.
