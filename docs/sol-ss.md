# ss socket snapshots

`ss` and `netstat` share `loadables/ss.c`. This work builds on the integrated
netstat backend fixes; integrate it after those changes and run both entry
points together. The `bss_opts` layout and exported `bss_run` interface are
unchanged. Build selection explicitly includes `ss,netstat`, matching the
netstat companion declared in `config/helpers.json`.

The supported surface is numeric TCP/UDP/Unix snapshots (`-t`, `-u`, `-x`),
listening or all states (`-l`, `-a`), and process annotations (`-p`). No family
flag means TCP, and no state flag means all states. `-l` takes precedence over
`-a`. This is the documented subset, not full iproute2 compatibility: `-4`,
`-6`, expression filters, name resolution, extended information and JSON are
not implemented. IPv4 and IPv6 records are both exercised through `-t` and
`-u`.

The ss frontend now flushes stdout, reports buffered write errors (including
`--version`), and clears the previous invocation's stdio error indicator.
The shared backend requests and decodes `UNIX_DIAG_RQLEN`, so Unix listeners
report their backlog and connected sockets report queued data. Malformed Unix
families, attribute streams and short queue attributes reject the dump and
trigger atomic per-family proc fallback. Short request writes and proc header
read errors also fail correctly. Existing netstat assertions now expect the
real Unix listener backlog and full proc fallback on malformed attributes.

The proc Unix table has no queue fields; zero remains a placeholder on that
route. Proc TCP listeners likewise expose current queues rather than netlink's
maximum backlog. Unix peer identity is not rendered (the existing `*` column
is preserved). Process annotation is a best-effort snapshot: denied PID
directories and descriptors disappearing during the scan are skipped. These
are explicit interface limits, not claims of atomicity across the live kernel
and proc filesystem.

## Reproduction

Set `CAMPAIGN` to the campaign directory and `EVIDENCE` to a private output
directory. Build and timing steps must use their resource gates:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include ss,netstat --name sol-ss
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  bash tests/sol-ss-build-fixtures.sh "$EVIDENCE"
python3 tests/sol-ss-behavior.py --binary out/bash-sol-ss \
  --shim "$EVIDENCE/ss-shim.so" --output "$EVIDENCE/correctness.json"
python3 tests/sol-netstat-behavior.py --binary out/bash-sol-ss \
  --shim "$EVIDENCE/ss-shim.so" --output "$EVIDENCE/netstat-correctness.json"
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-ss.py --binary out/bash-sol-ss \
  --shim "$EVIDENCE/ss-shim.so" --output "$EVIDENCE/benchmark.json"
```

For targeted ASan/UBSan runs, set `BASH_ENV` to `ss-sanitize-env.sh`, preload
the runtime listed in `ss-asan-path`, set
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`, and run both correctness scripts. The module
contains the production source pair. Leak detection for Bash lifetime
allocations is disabled; descriptor cleanup is checked separately over 100
calls in one persistent shell.

## Coverage and measurement boundaries

The test shim intercepts transport calls and proc paths, retaining the real
production parser, filters, process map and renderer. Fixtures independently
encode messages and expected output. Successful netlink tests deny proc tables
to prevent fallback from silently passing. Multipart replies span separate
receives, with ACKs, EINTR and unmatched sequences. Error cases include missing
DONE, short messages, dump interruption, truncation, invalid lengths, explicit
kernel errors, malformed Unix attributes, and partial dumps discarded before
fallback. Proc fixtures cover all TCP states, endpoints and nonzero queues,
malformed rows, denied tables, read errors and empty snapshots.

Live checks own IPv4/IPv6 loopback TCP listeners/connections and UDP sockets,
plus private Unix stream sockets. They verify exact owned endpoints, queues,
PID/FD annotations and selector inclusion/exclusion on both netlink and forced
proc routes. Where available, system ss records selected by the owned PID/FD
are checked for matching local endpoint, state and queues. Unrelated host
records never establish correctness. Queued TCP and Unix data are created by
the fixture itself. All resources are closed by the harness.

Timing first validates both routes for both workloads. One warmup precedes
seven samples, with ten calls sharing a shell per sample and an empty PATH.
The large workload independently specifies every byte of 10,000 connected TCP
rows, supplied as both a multipart netlink dump and a fixed proc table. Every
status and every repeated output must match. The small live UDP snapshot
contains two owned sockets; host UDP rows are counted but are not an oracle.
Every pass records total socket count and output bytes. Live timings include
host table work and may vary with host sockets.

Reports record CPU affinity, all sample durations, fixture/source/binary/shim
hashes, versions, options and reset rules. These are wall times including
shell startup and output capture. There is no external timing ratio or claimed
speedup: the historical starting evidence had no measured ss workload.

## Recorded validation

The starting binary failed 10 of the initial 74 ss checks, including buffered
write errors, malformed Unix replies and Unix queues. After the fixes and
additional state/read-error cases, all 80 ss and 63 netstat checks passed,
both natively and under ASan/UBSan. System ss was available for the six live
netlink selector comparisons.

On the recorded Linux x86-64 run, CPU affinity was fixed to CPU 11. Each sample
contains ten calls; seven samples followed a validated warmup:

| Workload | Route | Sockets / output bytes per call | Median batch ms | Min–max ms |
| --- | --- | ---: | ---: | ---: |
| Live UDP snapshot | Netlink | 13 / 980 | 3.74 | 2.28–4.99 |
| Live UDP snapshot | Proc | 13 / 980 | 5.97 | 5.71–7.32 |
| Fixed connected TCP table | Netlink | 10,000 / 750,077 | 104.44 | 93.47–109.64 |
| Fixed connected TCP table | Proc | 10,000 / 750,077 | 254.65 | 248.16–265.99 |

Two of the 13 live UDP sockets belonged to the workload. The fixed netlink
input contains 880,032 bytes across the two family dumps; the fixed proc input
contains 879,904 bytes across the two tables. All 28 measured batches passed
their per-invocation status and output checks. Raw reports are retained in the
campaign task evidence, not in historical benchmark datasets.
