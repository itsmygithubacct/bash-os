`bashsyslogd` receives datagrams on an AF_UNIX socket, appends a timestamp,
local hostname, and sanitized payload to `messages`, and appends the same
record to one facility stream. Numeric PRI facility 0 selects `kern.log`,
4 or 10 selects `auth.log`, and other or malformed priorities select `syslog`.
The facility filenames default to siblings of `--output`; explicit stream
options override them. Equal output and stream path strings produce one copy.
Existing contents are appended. C0 controls and DEL become spaces, except TAB;
bytes 128–255 remain unchanged. Payloads are opaque beyond the leading PRI.

The receive cap is 8192 bytes. A full receive buffer triggers one warning per
invocation, including an exactly fitting datagram. Larger datagrams retain
only their first 8192 bytes. Empty datagrams create no log record and satisfy
`--once`. Socket mode is checked after binding. Existing socket paths are
replaced; files, symlinks, directories and FIFOs are refused. Shutdown removes
only the socket inode created by this invocation. `SIGTERM` and `SIGINT` stop
the daemon; its prior signal dispositions are restored before it returns.

`--config` accepts literal `BASHSYSLOGD_FORWARD=value` assignments, whitespace,
comments, and single or double quotes. It does not evaluate shell expressions.
The last assignment wins; an empty value disables forwarding. Missing files
or keys leave the current setting alone. Unterminated quotes, trailing garbage,
embedded NUL, and oversized values are rejected. An explicit `--forward` takes
precedence at startup. `SIGHUP` reloads configuration; invalid configuration or
an unresolvable replacement leaves the current working destination intact.
Parsing and sanitization use ASCII rules without changing the shell's locale.
Timestamps use English month names and the local timezone.

UDP copies contain the sanitized payload only, with no added envelope or
newline. A successful UDP send provides no delivery acknowledgement. Receiver
socket overflow can therefore lose copies without creating queue entries.
Synchronous send failures append the original payload as lowercase hex plus
newline to `--queue`. Each N-byte payload occupies `2*N+1` queue bytes.
`--queue-max-bytes` bounds admission; zero disables it. A full or unwritable
queue drops the forwarding copy while local routing continues, prints a
diagnostic, and makes the eventual daemon exit status fail. Local open,
write, or close errors also make that status fail. Merely queueing a failed
forward does not fail the daemon.

Replay occurs at startup, after SIGHUP, and during idle or busy operation at
one-second monotonic-clock intervals. Pending records precede new arrivals.
After the first unsuccessful replay send, subsequent valid records stay in
FIFO order. A lowered admission limit does not delete existing records.
Malformed, oversized, NUL-containing, and incomplete hex records are discarded
without consuming the following record. Replay writes a private temporary file
and replaces the queue only after successful close. Rewrite failures retain
the original queue and cause a failing final status; already sent records can
repeat after such a failure. The spool is a single-daemon, best-effort queue,
not an acknowledged or crash-durable delivery protocol. It does not fsync,
coordinate concurrent writers, or promise delivery after SIGKILL or power loss.
DNS resolution uses blocking `getaddrinfo`, so network resolver delays may
extend service or shutdown latency beyond the socket poll interval.

Reproduce the focused checks with a targeted build, then the task fixture and
sanitizer module. Use the campaign resource gates for every compilation and
measurement (the commands below omit the campaign-specific gate prefix):

```sh
./build.sh --include bashsyslogd --name sol-bashsyslogd
bash tests/sol-bashsyslogd-build-fixtures.sh "$EVIDENCE"
python3 tests/sol-bashsyslogd-check.py out/bash-sol-bashsyslogd \
  --fixture "$EVIDENCE/faults.so"
python3 tests/sol-bashsyslogd-check.py out/bash-sol-bashsyslogd \
  --fixture "$EVIDENCE/faults.so" --module "$EVIDENCE/bashsyslogd-sanitize.so" \
  --asan "$(cc -print-file-name=libasan.so)"
python3 bench/sol-bashsyslogd.py --binary out/bash-sol-bashsyslogd \
  --fixture "$EVIDENCE/faults.so" --runs 7 --output "$EVIDENCE/timing.json"
```

No companion loadables or common-helper edits are required. Correctness checks
run shells with an empty PATH and use only owned child daemons, private socket
and log trees, loopback UDP, and `/dev/full`. The preload fixture fixes the file
timestamp for exact full-file byte assertions and injects send/rewrite failures
only when task-private marker files exist. It executes the production builtin;
the benchmark uses real AF_UNIX reception, routing, spool I/O, and loopback UDP.

The benchmark reports syscall-fixture/API timings without an external ratio.
There is no equivalent-output rsyslog/syslogd reference fixture here. Each case
has a warm-up and at least seven validated samples on one recorded CPU, with
fresh sockets, files and shell processes. It records source, executable,
fixture and harness hashes, environment versions, work counts, every elapsed
sample, and sample distributions. The sustained case sends 20,000 distinct
128-byte datagrams across four PRI values, verifies all 40,000 local records
and UDP copies, and limits outstanding UDP copies to 32. This is controlled
end-to-end throughput, including sender/receiver coordination, rather than a
maximum daemon receive rate. The overload case sends 4096 datagrams while the
small UDP receiver is not reading, then validates the exact delivered subset
and loss. The bounded-spool case injects EAGAIN, sends 4096 datagrams, retains
64 records in a 16,448-byte queue, checks every dropped copy diagnostic, then
restores real loopback sends and verifies idle recovery and cleanup. Producer pauses at 16, 32, 48 and 64 records verify queue growth
against independently predicted hex sizes. Every
case uses a 4096-byte requested sender buffer and fills the paused owned daemon's UNIX receive queue before timing to
verify actual sender backpressure, then counts additional EAGAIN retries.

Validated measurement, 2026-10-19: Intel Core i7-9850H, CPU 11,
Bash 5.3.15, GCC 14.2.0. All three warm-ups and 21 timed samples passed.
These are syscall-fixture timings with a fixed timestamp; there is no
external reference ratio or before/after speedup claim.

| Workload | Input messages / bytes | Routed file bytes | Routing seconds, median [min–max] | UDP copies received | Forward copies lost |
|---|---:|---:|---:|---:|---:|
| sustained | 20,000 / 2,560,000 | 6,120,000 | 0.861889 [0.786881–1.027074] | 20,000 | 0 |
| udp-overload | 4,096 / 524,288 | 1,253,376 | 0.139003 [0.123506–0.151844] | 9 | 4,087 |
| bounded-spool | 4,096 / 524,288 | 1,253,376 | 0.124325 [0.108787–0.137763] | 64 | 4,032 |

The sustained median is 23,205 received and routed messages/s, with
40,000 local records and 2,560,000 forwarded payload bytes per pass.
Every workload had zero receive or routing loss. The stopped-child UNIX
socket accepted 11 datagrams before the sender observed EAGAIN; the
report also records retries during ingress. The overload receiver retained
the exact first nine datagrams (1152 bytes), lost 4087 copies, and left no
spool, demonstrating that successful UDP sends do not acknowledge delivery.

The bounded-spool case measured 0, 4112, 8224, 12,336 and 16,448 bytes
at 0, 16, 32, 48 and 64 sent records. It stayed at capacity, reported
4032 dropped copies, then forwarded the exact 64 retained datagrams
(8192 payload bytes) after recovery. Queue and socket cleanup passed.
Routing time in that case includes the deliberate producer checkpoints;
forward completion and queue-recovery time are recorded separately.

The first report also passed all output checks. Its default UNIX sender
buffer allowed 278 stopped-child datagrams, so its first queue observation
was already at capacity. The final report uses the smaller sender buffer
and explicit growth checkpoints described above. Both reports are retained
separately in task evidence. The behavioral driver passed all 16 groups
both natively and with ASan/UBSan. Sanitizers instrument the production
loadable module; host Bash allocations are excluded from leak detection.
Exact descriptor-set comparisons verify cleanup across repeated calls.

Measured source SHA-256: `c7f79654cc7c5fdec11d1777ef88d19110886ec7d3cd6f05dbcec80b6b4c8c49`.
Measured executable SHA-256: `c6f7c8402f17431e450aafff4b748b7ba1e02019070b03390ba990652a5217e7`.
