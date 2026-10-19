# Cluster membership

`cluster` runs an authenticated membership service on IPv4 loopback. The shell
that calls `init` or `join` owns a small listener child; keep that shell alive
while it participates. Each peer needs a different, existing parent directory
and a private state directory (0700). No other command needs to be built:

```sh
./build.sh --include cluster --name cluster
```

The build selects the existing `_monocypher` helper through
`config/helpers.json`. There are no changes to shared helper implementations.

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

For this change, the native real-peer checks and the production-module
ASan/UBSan checks passed, including the independent Python packet-MAC oracle.
The starting binary fails the real-listener assertion. Performance qualification
remains incomplete: the campaign measurement gate did not start either queued
benchmark during sustained host pressure and lock waits. The owned waiting jobs
were stopped, their logs preserved, and no timing, speedup, loss-rate or timeout
sample results are claimed. The historical reports remain unchanged.

After resources are available, run the unchanged historical case first, then
this task's stricter comparison and live API workload, each through the required
measurement gate:

```sh
python3 bench/loadables.py --binary out/bash-cluster-before \
  --only cluster-members --passes 40 --runs 7 --output BEFORE.json
python3 bench/sol-cluster.py --binary out/bash-cluster-final \
  --before-binary out/bash-cluster-before --streaming-report PAIRED.json \
  --runs 7 --joins 8 --pings 100 --output API.json
```
