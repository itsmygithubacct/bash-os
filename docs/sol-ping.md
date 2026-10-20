# ping echo contract and focused validation

`ping` sends IPv4 or IPv6 echo requests without starting another process. Echo
probes try a raw socket first and a Linux datagram ping socket after EPERM or
EACCES. For a datagram socket, the connected socket's local port supplies the
identifier rewritten by the kernel. Neither path changes host capabilities or
kernel settings.

`-c` accepts 1–10000 probes (default 5). `-W` sets each reply timeout and `-i`
sets the minimum time between sends; both accept 0.1–60 seconds. Waiting for a
reply consumes the interval. `-w` accepts an overall deadline of 0.001–86400
seconds, measured from the probe loop's start with the monotonic clock. It bounds
both reply waits and inter-probe waits. `-q` suppresses per-probe output. Invalid
arguments return 2; normal completion returns 0 if any reply arrived, otherwise
1. Socket, clock, send, receive and output failures return 1, including failures
after a successful reply. `-w` with traceroute mode is rejected.

A reply must match the current request's identifier, sequence and entire 56-byte
payload, including its send timestamp. Duplicate and stale replies are ignored;
they cannot satisfy a later probe or drive packet loss below zero. IPv4 raw
replies also require a valid IPv4 version, header length, total length, protocol,
source, unfragmented packet and IP/ICMP checksums. Datagram replies require the
same ICMP checksum and request match. IPv6 checksum generation and validation
belong to the kernel ICMPv6 socket. Both families check the source address,
packet length, reply type/code, receive truncation flags and deadline before
counting a reply. Sockets close on normal/error returns and Bash signal unwind.

The focused tests include the production C file in a loadable fixture that
replaces socket and monotonic-clock calls. It never opens a network socket and
asserts every destination is exactly `127.0.0.1` or `::1`. A separate byte-wise
checksum oracle checks every generated IPv4 request. Fixtures cover raw and
datagram paths, identifier rewriting, wrong identity/payload/timestamp,
checksums, malformed/truncated headers and ancillary data, duplicates, partial
and total loss, reply timeout, deadline expiry, EINTR/EAGAIN, permissions,
unsupported sockets, short writes and injected syscall/clock errors. All 32
existing selftest assertions remain. Tests also exercise invalid input, numeric
boundaries, the default count, 10000 probes, an empty PATH, repeated calls,
`/dev/full` recovery, descriptor counts and an interrupt of an owned shell.
Native checks send only to IPv4/IPv6 loopback. ASan/UBSan instruments the
production code and fixture; the hosting Bash is the normal targeted build.
The final run passed 118 normal shell cases and 111 instrumented shell cases,
including the 32 original selftest assertions. An earlier native run exposed a
trapped-SIGINT wait defect; the final run verifies that the socket closes before
the caller's interrupt trap runs.

Build and run with the campaign's supplied gate and an evidence directory:

```sh
python3 "$GATE" build -- ./build.sh --include ping --name sol-ping
python3 "$GATE" build -- tests/sol-ping-build.sh "$receipt/fixtures"
python3 tests/sol-ping-check.py out/bash-sol-ping "$receipt/fixtures"
python3 tests/sol-ping-check.py out/bash-sol-ping "$receipt/fixtures" --sanitize
python3 "$GATE" bench -- python3 bench/sol-ping.py \
  --binary out/bash-sol-ping --fixtures "$receipt/fixtures" \
  --runs 7 --output "$receipt/bench.json"
```

`config/helpers.json` declares no companion loadable for `ping`. The targeted
selection stages the default `_jsmn` helper and links Bash's default libm. No
common helper changes are required.

The benchmark uses one full warm-up and seven validated samples on a recorded,
single CPU. Each shim sample makes 20 calls of 10000 probes, with fake intervals
and a fixed 0.250 ms virtual reply delay. Wall time per packet measures production
request construction, validation, accounting and shim overhead, including shell
startup; the virtual delay is not network RTT. Each native sample makes one call
of 16 loopback probes with a 100 ms interval. Its reported RTT statistics are
real echo RTT; its command wall time includes pacing. Every repetition checks
status, exact transmitted/received counts, zero loss, and the expected sequences
or shim counters. Raw reports retain outputs, all samples, versions, affinity,
source hashes, fixture hashes and binary hashes. There is no equivalent external
reference measurement or speedup claim.

Measured on 2026-10-19 with Bash 5.3.15, GCC 14.2, Linux 6.12 and an
Intel Core i7-9850H, pinned to CPU 11:

| Metric | Probes per sample | Median | Sample min–max |
|---|---:|---:|---:|
| IPv4 shim processing | 200000 | 426.45 ns/packet | 422.87–428.16 ns/packet |
| IPv6 shim processing | 200000 | 321.05 ns/packet | 318.27–355.34 ns/packet |
| IPv4 reported average loopback RTT | 16 | 0.069 ms | 0.059–0.078 ms |
| IPv6 reported average loopback RTT | 16 | 0.063 ms | 0.060–0.077 ms |

All four cases and all their repetitions passed validation. The native command
wall-time medians were 1.507 seconds per 16 probes, dominated by the 100 ms
interval. Native runs had no effective capabilities and used datagram ping
sockets; raw-socket paths were fixture-backed. The raw `bench.json`, compiler
receipts and correctness logs remain in the task evidence directory.
The measured native binary SHA-256 was
`76a4314a9ad371e821c214be8dc1b754d9ec303043c614ac5f30b871c58290c3`.
The production source SHA-256 was
`7b793a594f1184c4dca4c326174187ff18a11f0fcec083473ea8c441de82fef3`.

Scope is IPv4/IPv6 echo software behavior on Linux. Traceroute retains its
existing codec selftests; complete traceroute/hop-error qualification, remote
routing, DNS/IDN behavior, non-Linux socket semantics and actual network-device
qualification are outside this loopback-only task. The synchronous echo loop
intentionally ignores late replies after their probe timeout. It does not claim
full iputils option or output parity.
