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

The frontend in `loadables/netstat.c` flushes stdout before
returning, propagates output failures, and clears a previous call's stdio error
indicator at entry. This includes `--version`. A failed write must return failure
while allowing another invocation in the same shell to succeed.

The scope is the documented numeric TCP/UDP/Unix subset, including short and
long aliases. It does not claim complete net-tools compatibility, service-name
resolution, routing/interface tables or IPv4/IPv6 selection options. Unix queue
fields come from `UNIX_DIAG_RQLEN` when netlink supplies it; the proc Unix table
does not expose queues and retains zero placeholders. The current
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

## Backend behavior

The shared backend validates netlink message lengths and dump completion,
including interrupted dumps and error payloads. Each family is buffered until
its dump completes; a failed dump is discarded before trying that family's
proc table. If both transports fail, the command fails. This avoids duplicate
rows after a partial netlink failure.

Proc and netlink endpoints use the same numeric rendering. UDP listening means
unconnected sockets; proc Unix states and listen flags are mapped separately
from TCP states. Malformed proc addresses are skipped. Integration must retain
both `netstat.c` and the corresponding `ss.c` backend changes.
