# Controlled mail submission and delivery

`tests/sol-mail-check.py` exercises the production `mail` builtin with private
Unix sockets, queues and a strict Python SMTP server bound to `127.0.0.1` on
an ephemeral port. Every shell has an empty `PATH`. No external email, system
spool, aliases file or mail configuration is used.

The fixture checks exact envelope order, queue IDs and metadata, file modes,
headers and bodies (including NULs, LF/CRLF, empty messages and bodies larger
than 1 MiB). SMTP checks include exact commands, fragmented multiline replies,
CRLF conversion, dot stuffing, final DATA acknowledgement and QUIT. All six
reply stages have independent 451/550 failures followed by successful retries
from unchanged queue files. Mixed recipient results, malformed replies,
missing queue members, invalid arguments, failed stdout writes and repeated
calls are covered. Submission frames are fragmented and malformed, truncated,
oversized, duplicated and injected with control/NUL characters. Daemon tests
check occupied paths, peer disconnects, interrupted incomplete frames,
SIGINT/SIGTERM, restart in the same shell, signal restoration, socket cleanup
and stable descriptor counts. Original alias compilation/expansion assertions
remain, including empty input and invalid input preserving the previous DB.

The implementation now preserves byte lengths and the original header/body
separator. Older queue entries without separator metadata retain the previous
LF reconstruction rule. Missing bodies fail delivery instead of becoming empty
messages. Queue inspection writes the complete original message after the
envelope and `--` marker. Framing rejects invalid lengths, ordering and fields.
Delivery reports failed recipients through its exit status even when other
recipients succeeded; stdout lists only recipients committed by the sink.
Output failures return a failure status; a submission or SMTP transaction may
already have committed, so callers must account for that ambiguity.

`deliver-fd` is a transport primitive. The caller supplies an already connected
socket, sender, queue ID and recipients. It leaves the queue entry intact on
success and failure. A runner must persist delivered recipients, retry only
undelivered recipients after temporary failures, handle permanent failures and
remove completed entries. This task tests controlled retry/recovery through
that primitive; it does not implement an autonomous queue scheduler, MX lookup,
or bounce policy. TLS, DKIM and internet interoperability are outside these
plain SMTP fixtures. Binary bodies are checked through the controlled transport;
this is not a claim of BINARYMIME capability negotiation. No hardware or live
mail service is required for this software-path scope.

Build only `mail`: `config/helpers.json` selects `_mbedtls`, `_monocypher` and
baseline `_jsmn`, with `-lpthread`. No companion builtin or shared-helper edit
is required. In the commands below, `CAMPAIGN` is the campaign directory
containing `scripts/gated.py`, and `BASHOS_TASK_DIR` is the evidence directory.
Run all compilation through the campaign build gate:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- ./build.sh --include mail --name sol-mail
python3 tests/sol-mail-check.py out/bash-sol-mail
python3 "$CAMPAIGN/scripts/gated.py" build -- bash tests/sol-mail-sanitize-build.sh
SOL_MAIL_LOAD_ENV="$BASHOS_TASK_DIR/sanitize/load.sh" \
SOL_MAIL_ASAN_LIB="$(cat "$BASHOS_TASK_DIR/sanitize/asan-runtime.txt")" \
python3 tests/sol-mail-check.py out/bash-sol-mail
```

The sanitizer builder requires `BASHOS_TASK_DIR` and a completed targeted build;
it compiles only this command and its declared helpers, sequentially. The
correctness driver never compiles. Leak detection is disabled for the embedding
Bash runtime; persistent descriptor and daemon cleanup have explicit assertions.

`bench/sol-mail.py` measures four boundaries independently: direct enqueue,
Unix-daemon enqueue, prequeued SMTP delivery, and Unix submission through SMTP
acknowledgement. Each sample uses 16 identical messages, two recipients per
message, a fresh private queue and persistent empty-PATH shells. It records a
warm-up and seven samples, per-message latency distributions, message/byte
counts and rates, source/binary/fixture/harness hashes, versions and fixed CPU
affinity. Every message must pass the independent queue/content oracle before
its sample is accepted. Setup and between-message content checks are excluded;
Python control, socket connection, SMTP acknowledgement, QUIT and sink join
are included. Rates divide work by the sum of those boundary latencies and do
not describe the full harness wall time.

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- python3 bench/sol-mail.py \
  --binary out/bash-sol-mail --output "$BASHOS_TASK_DIR/bench-after.json"
```

These are local API timings with no external ratio. A standalone sendmail or
mailq command does not implement equivalent work across these boundaries.
Historical alias timings remain separate; the existing `bench/loadables.py`
case can be reproduced unchanged with `--only mail --passes 32 --runs 7` under
the bench gate. Raw logs and reports are stored in the task evidence directory,
not historical datasets or generated catalogs.

Plain submission and SMTP socket writes suppress SIGPIPE per send, preserving
the shell and its signal dispositions when the peer disconnects. Unexpected
3xx recipient replies are temporary failures, including mixed-recipient results.
`tests/astra-mail-disconnect.py BINARY` exercises a closed peer with a private
socket pair and checks shell survival and the unchanged queue.
