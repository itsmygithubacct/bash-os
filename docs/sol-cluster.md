# Cluster membership

`cluster` runs an authenticated membership service on IPv4 loopback. The shell
that calls `init` or `join` owns a small listener child; keep that shell alive
while it participates. Each peer needs a different, existing parent directory
and a private state directory (0700). No other command needs to be built:

```sh
./build.sh --include cluster --name cluster
```

The build selects the existing `_monocypher` helper through the five-line
`config/helpers.json` dependency entry. Startup also includes the existing
`loadables/common/child-wait.h`; build.sh already stages that header. There are
no changes to shared helper implementations. The guard blocks Bash's SIGCHLD
reaper during fork, readiness and failed-child reaping, so a failed listener's
PID cannot be reused before cleanup signals it. The child restores the inherited
signal mask before serving. Success releases the guard without waiting for the
long-lived listener; the shell's handler, pending job signals and traps survive.

In the first persistent shell:

```sh
export BASHCLUSTER_STATE_DIR=/private/seed
cluster init -p 5450
cluster status
cluster members
```

In a second persistent shell, using the seed's generated key file:

```sh
export BASHCLUSTER_STATE_DIR=/private/peer
cluster join 127.0.0.1:5450 -k /private/seed/private_key
cluster members
cluster ping 127.0.0.1:5450
cluster ping NODE_ID_FROM_MEMBERS
cluster leave
```

`init -k FILE` accepts a shared key supplied by the caller. Key files contain
exactly 64 lowercase hexadecimal digits, with an optional final newline.
`init` generates 32 bytes using the kernel random API when no key is supplied.
`join -k FILE` is required. Both verbs support `-p PORT`; port 0 asks the kernel
for an unused port. Join defaults to port 0 and init to 5450. Only numeric
`127.0.0.1:PORT` endpoints are accepted, avoiding DNS and off-host traffic.
The former `BASHCLUSTER_MOCK_SSH` bypass has been removed.

The seed owns a roster of up to 32 nodes including itself. Members are lines of
`NODE_ID 127.0.0.1:PORT`, including the local node. Successful join uses the
seed's real cluster ID and makes both participants' rosters agree. Duplicate
join or init fails without adding a row. A joining node cannot replace another
node's ID or endpoint. Joining through a leaf is rejected. The seed is a single
coordinator; there is no election, routing, SSH transport or distributed
consensus in this interface.

Every wire packet has a fixed versioned format and a keyed BLAKE2b-256 MAC;
key bytes are never transmitted. Replies echo a random request nonce. Invalid
sizes, versions, MACs, counts, node IDs and endpoints cannot add members.
A different key therefore fails the handshake, even when the port is live.
Any holder of the group key is trusted; this is not a hostile-member isolation
protocol or an encrypted transport. Request replay suppression is not provided.
Deployments across hosts or untrusted local users require a separately reviewed
transport and protocol extension.

`BASHCLUSTER_TIMEOUT_MS` sets the request deadline, from 50 to 5000 ms (default
500). A peer sends a heartbeat every quarter deadline and expires after three
deadlines without one. Roster changes propagate on heartbeat replies. Members
write a new snapshot only when it changes. If the seed disappears, surviving
leaves report `state=disconnected` and retain only themselves. An authenticated
heartbeat can recover the roster when a live seed resumes. Ping tests the
membership protocol and MAC, rather than the existence of an unrelated socket.
A failed request returns 1; invalid syntax returns 2.

Leave stops the local listener, notifies the seed when applicable, and removes
owned state files. Repeated leave succeeds. A kernel parent-death signal makes
an abruptly killed owning shell's listener perform the same cleanup. A listener
killed with SIGKILL cannot run cleanup: peers expire it, status reports
`state=stopped`, and `leave` or `init` recovers its stale local state. The `lock`
file stays to preserve the identity of the advisory lock. No PID read from disk
is signaled. Unrelated files in the state directory are preserved. Members and
status read snapshots; members retains support for streaming an offline roster
file. Writes use private temporary files and atomic rename, without durability
claims across power loss.

The service closes inherited descriptors and detaches its standard streams.
Commands work with an empty PATH and report output failures. Membership changes
may already have committed when their output cannot be written; inspect status
before retrying a mutating operation.

## Validation and measurement

`python3 tests/sol-cluster-membership.py out/bash-cluster` uses independent
persistent shells, ephemeral loopback ports, and private temporary directories.
It verifies three-peer membership transitions, node/endpoint ping, key mismatch,
duplicate join, timeout, non-protocol listeners, malformed authenticated and
unauthenticated packets, an independent Python MAC oracle, leave, owned-shell and listener death, seed disconnect,
stale recovery, repeated calls, FD cleanup, invalid input and output failure.
It never compiles fixtures or signals unrelated processes.
Failed handshake, immediate persistence failure and readiness EOF checks run
with a SIGCHLD trap and unrelated owned Bash jobs. They verify exit statuses,
trap and signal-mask preservation, listener reaping and stale-state recovery
with a forged `listener_pid` naming a still-live owned job.
`tests/sol-cluster-sanitizer-build.sh OUTPUT_DIRECTORY` separately builds the
production module and crypto helper with ASan and UBSan. In the campaign this
build must run through the build gate. Set `BASHOS_CLUSTER_TEST_MODULE` to the
resulting module and preload the ASan runtime named by `asan-runtime.txt` to run
the same checks through `enable -f`. The Bash runtime itself is uninstrumented;
leak detection is disabled for that runtime. The old version
assertion in `tests/misc-smoke.py` remains unchanged.

`bench/sol-cluster.py` uses the same real peers and an independently constructed
node-to-endpoint map. One warm-up and seven or more samples measure fixed work:
eight joins, eight additions observed by all three peers, eight removals observed
by the two survivors, and a batch of 100 authenticated pings. Every status and
output is checked. Deliberately blackholed pings are measured separately;
application request losses, expected timeouts, unexpected timeouts, and other
failures have separate counters. These are API timings without an external
ratio. Raw samples, fixture options/hash, CPU affinity, kernel and tool versions,
source hash, binary hash and exact work counts are recorded by the harness.
An owned UDP relay also drops every fourth request in a fixed 12-ping batch;
its independent request/reply/drop counts must match nine successes and three
expected timeouts. This loss case is separate from the fully blackholed case
and the direct successful ping batch.

Use `--streaming-report FILE --before-binary OLD_BINARY` to run a stricter
comparison first. It captures and compares every byte of all 40 roster streams
in each timed batch for both binaries and `cat`, with one warm-up and seven
samples. Its capture cost is shared by all implementations and differs from the
historical discard-output timing profile.

The existing `cluster-members` case in unchanged `bench/loadables.py` measures
40 complete streams of a fixed 20,000-row roster. Its `cat` comparison is valid
for that byte-streaming work only. It does not measure live membership or
validate a network protocol. Campaign measurements and conclusions are recorded
in the task evidence receipt; no historical dataset is overwritten.

The follow-up native real-peer checks and production-module ASan/UBSan checks
passed, including the independent Python packet-MAC oracle and the listener
ownership regression fixtures. The starting binary fails the real-listener
assertion. No shared helper implementation was changed.

The completed measurement used CPU 11 on an Intel Core i7-9850H, Linux
6.12.111+deb13-amd64, Bash 5.3.15, GCC 14.2.0, Python 3.13.5 and GNU cat 9.7.
Each case has one warm-up and seven measured samples. The fixed offline roster
contains 20,000 rows / 1,768,818 bytes, SHA-256
`6a7a5e850bb55e2f4ad45fb6e9e22b186981e29d58bbc752d7479909b977b057`.
The saved baseline source matches the campaign baseline's cluster.c. The final
source hash is `de228e52154c07abfef402adede8883434185330c2dabecdda73130ce5d3000a`;
the native binary hash is
`62df2e2091ba7d3a6bcc10d1cfcd1b8c949e30660f09a8c29450667e7b67395a`.
The evidence receipt records all source, binary, harness and fixture hashes,
options, resets, versions and raw distributions.

| Work per sample | Median ms | Range ms | Measured outcome across seven samples |
|---|---:|---:|---|
| 8 real joins | 12.961 | 11.335–13.543 | 56 successes |
| 8 additions observed by all three peers | 381.299 | 369.417–386.844 | 56 exact roster transitions |
| 8 removals observed by both survivors | 400.673 | 400.166–409.016 | 56 exact roster transitions |
| 100 direct authenticated pings | 11.645 | 10.882–15.388 | 700 successes, zero loss/timeouts |
| 1 blackholed ping | 200.523 | 200.456–200.944 | 7 expected timeouts, zero replies |
| 12 relay pings, every fourth dropped | 605.672 | 604.051–609.693 | 63 successes, 21 injected losses / expected timeouts |

No case had an unexpected timeout or validation failure. Addition/removal
measurements include heartbeat propagation, polling and snapshot reads; the
configured heartbeat is 50 ms. Join and ping exclude shell startup. Blackhole
and loss cases use the configured 200 ms request deadline and assert each
expected timeout completes in 150–900 ms. These are loopback API timings on a
shared host, with no equivalent external membership API or external ratio.
No off-host transport, hardware qualification, election or hostile-member
isolation is claimed.

The unchanged historical `cluster-members` reproduction validated builtin,
GNU cat and BusyBox cat, with medians 46.232, 92.080 and 80.296 ms respectively
for 40 streams sent to /dev/null. The strict paired capture workload validated
320 streams per implementation including warm-up: baseline 119.790 ms
(102.901–128.736), final 116.061 ms (107.712–139.955), GNU cat 120.630 ms
(103.244–133.577). The ranges overlap; no reproducible streaming bottleneck or
speedup is claimed, and no speculative performance change was added. Capture
and discard-output timings use different methods and must not be compared as a
paired speedup. Cat is equivalent only for these identical byte streams.

New raw reports, kept outside Git in the task evidence directory, are
`attempt-2-members-before.json`, `attempt-2-members-paired.json` and
`attempt-2-membership-api.json`. The independent report check confirms every
case status, all seven-sample distributions, the matching streaming fixture,
CPU affinity, artifact hashes, work counts and relay request/reply/drop counts.
Attempt-1 evidence and all historical datasets remain unchanged.

Reproduce with the campaign gates (builds must use the build gate separately):

```sh
python3 /path/to/gated.py bench -- python3 bench/loadables.py \
  --binary out/bash-sol-cluster-before --only cluster-members \
  --passes 40 --runs 7 --output BEFORE.json
python3 /path/to/gated.py bench -- python3 bench/sol-cluster.py \
  --binary out/bash-sol-cluster-attempt-2 \
  --before-binary out/bash-sol-cluster-before --streaming-report PAIRED.json \
  --runs 7 --joins 8 --pings 100 --output API.json
```
