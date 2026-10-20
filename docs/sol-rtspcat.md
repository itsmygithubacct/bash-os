# rtspcat loopback qualification

`rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-t SECS] [-v]` receives H.264
RTP over an RTSP TCP connection. Each output record is a four-byte unsigned
big-endian length followed by Annex-B NALs, each prefixed by `00 00 00 01`.
SDP SPS/PPS fill missing parameter sets before an IDR. `-n 0` streams without
a unit limit. `-k 0` disables keepalive; the default is 25 seconds. `-t` sets
a positive read deadline in seconds, default 15. Invalid numeric arguments
return usage status 2.

The implementation now tracks RTP sequence numbers, including wraparound.
Duplicate and late packets are ignored. A forward gap discards the current
access unit and fragmented NAL; assembly resumes on a new timestamp. There
is no jitter queue or reordering latency: TCP wire order is authoritative.
Malformed RTP, incomplete fragments, invalid aggregation lengths and
unsupported packetization invalidate the affected unit. A STAP-A is validated
in full before any of its NALs are appended. Marker bits finish units; a new
timestamp also finishes an undamaged unit from a sender without marker bits.
EOF returns failure and discards any unfinished unit. `-n` applies at either
boundary and never flushes an extra unit during cleanup.

AU and FU buffers each have an 8 MiB limit, including Annex-B prefixes for the
AU. They grow geometrically and are reused. Oversize units fail rather than
silently truncating. RTSP headers are limited to 8191 bytes and response bodies
to 65535 bytes. Negative, overflowing, ambiguous duplicate and malformed
Content-Length values fail before reading a body. A 16 KiB socket buffer avoids
a poll/read system-call pair for each RTSP header byte. Read deadlines use the
monotonic clock, including across interrupted polls and partial body reads.
Keepalives run during idle reads as well as active streaming.

Authentication covers Basic challenges and MD5 Digest with no qop or
`qop=auth`, including nonce counts, opaque and a qop choice list. Unsupported
algorithms and qop values fail explicitly. Credentials are omitted from request
URIs. Authentication, session, input buffering and packet state are local to
each invocation. Authenticated requests are formatted directly into a bounded
request buffer; there is no intermediate unbounded string copy. SETUP's
negotiated TCP channels are honored. Output failures, including EPIPE, return
failure; SIGPIPE disposition is restored before returning to Bash.

The command needs no companion loadable, common helper or external library.
`config/helpers.json` has no rtspcat entry. A targeted build is:

```sh
python3 /home/pleb/research/bash-os/loadable-completion-20261019/scripts/gated.py build -- \
  ./build.sh --include rtspcat --name sol-rtspcat
python3 tests/sol-rtspcat-loopback.py --binary out/bash-sol-rtspcat
```

The command-owned fixture checks exact independently constructed output bytes
and request URIs, CSeq, session headers, transport, Range, challenge hashes,
keepalive bodies and TEARDOWN. Coverage includes all three H.264 payload
forms, sequence wrap, channel negotiation, ignored RTCP, missing one parameter
set, loss, reordering, duplicates, truncated input, bad RTP padding/extensions,
malformed STAP-A/FU-A, timestamp boundaries, EOF, timeout, count limits,
invalid options/URLs, long authenticated track URIs, and output failures.
Native calls use an empty PATH. Twenty-four calls in one Bash process alternate
successful output and `/dev/full`, followed by eight failed handshakes;
before/after FD counts and the PIPE trap
must match. A real pipe without a reader checks EPIPE and shell survival.

`tests/sol-rtspcat-core.c` includes the production source and instruments only
its allocator boundary. It asserts geometric allocation counts, the maximum
allocation size, peak/live allocation bounds, OOM propagation and cleanup,
and drives 100,000 deterministic adversarial RTP inputs. It also checks MD5
known-answer vectors and repeated SDP parameter replacement. ASan/UBSan with
leak detection run that harness and the full standalone network fixture:

```sh
BASHOS_TASK_DIR=/path/to/local/evidence \
python3 /home/pleb/research/bash-os/loadable-completion-20261019/scripts/gated.py build -- \
  bash tests/sol-rtspcat-sanitize.sh
```

`bench/sol-rtspcat.py` uses the same fixed generated stream and independent
framed byte oracle, with one warmup and at least seven samples. Every pass
validates all output bytes, status and the RTSP method sequence. It measures
process launch through complete validated streaming, and launch through the
first complete framed unit. It records validated frames/bytes, sample
distributions, fixed CPU affinity, versions and source/binary/fixture hashes.
It requires a single pinned CPU and performs no builds:

```sh
python3 /home/pleb/research/bash-os/loadable-completion-20261019/scripts/gated.py bench -- \
  python3 bench/sol-rtspcat.py --binary out/bash-sol-rtspcat --runs 7 \
  --frames 1200 --output /path/to/local/evidence/benchmark.json
```

These are loopback software-path qualifications. No external camera,
non-loopback network, decoder or physical appliance is used. IPv6 literals,
UDP transport, TLS, other codecs, STAP-B/MTAP/FU-B and non-MD5 Digest are outside
this command's qualified subset. Loss recovery drops damaged frames rather
than reconstructing missing media. DNS/connect and blocked output writes are
not governed by the read timeout. Camera interoperability and decoded picture
quality require separate device qualification. API timings include the Python
server and shell startup; there is no matched external-tool ratio.

Root-relative SDP control paths use the Content-Base authority, discarding
its path. `tests/astra-rtspcat-control.py BINARY` checks the exact authenticated
SETUP URI and output frame against a private loopback server.
