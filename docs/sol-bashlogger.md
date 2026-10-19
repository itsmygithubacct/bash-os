# bashlogger private datagram coverage

`bashlogger` sends one AF_UNIX datagram per successful invocation. It uses
`BASHLOGGER_SOCKET` when nonempty, otherwise `/dev/log`. Tests and measurements
bind a private temporary socket and never send to the host syslog service.

The wire format is `<PRI> TAG: MESSAGE`, or `<PRI> TAG[PID]: MESSAGE` with
`-i`/`--id`. There is no terminating newline or NUL, timestamp, or hostname.
The default is `<13> user: MESSAGE` (`user.notice`). This is a small
logger-style API, not a claim of complete util-linux logger CLI/RFC parity.

Priority accepts a decimal complete PRI from 0 through 191, a named severity
with the user facility, or `facility.severity`. In the pair, facilities may
be decimal 0 through 23 and severities decimal 0 through 7; either component
may instead be a name. Names are case insensitive. Facilities are `kern`,
`user`, `mail`, `daemon`, `auth` (`security`), `syslog`, `lpr`, `news`, `uucp`,
`cron`, `authpriv`, `ftp`, and `local0` through `local7`. Severities are
`emerg` (`panic`), `alert`, `crit`, `err` (`error`), `warning` (`warn`),
`notice`, `info`, and `debug`. A pair becomes `facility * 8 + severity`.
Invalid priorities fail with status 2 before any socket is opened.

`-t`/`--tag`/`--tag=` set the tag; `-p`/`--priority`/`--priority=` set priority.
Arguments join with one space between each pair, preserving empty arguments.
`--` terminates option processing, including for messages beginning with `-`.
An explicit empty message is valid. With no message arguments, stdin supplies
one message; internal bytes/newlines are preserved and one trailing LF or CRLF
is removed. Empty stdin is an error. Read errors fail with status 1; embedded
NUL input fails with status 2. Stdin EOF/error state is cleared on each read.

Message arguments, including joining spaces, have a 2047-byte limit. Stdin has
the same limit before removing its trailing newline. A formatted datagram has
a 3071-byte limit. Oversized input fails with status 2 and sends nothing, rather
than silently truncating. Socket paths which cannot fit in `sun_path` fail with
status 1 and cannot address a different socket by truncation. Socket/open/send
failures return 1; interrupted sends retry and short sends fail. Every call
closes its socket, including failed sends and failed CLOEXEC setup.

## Focused validation

The integration test uses the actual production builtin with an empty PATH.
It checks all named facility/severity combinations, all numeric PRIs, numeric
pairs, mixed pairs, aliases, exact tag/PID bytes, whitespace/UTF-8/newlines,
explicit empty operands, option errors, input and formatted-size boundaries,
stdin read errors and repeated stdin use, missing/regular-file destinations,
and a live endpoint at the old truncated-path target. A persistent shell sends
200 valid messages and makes 400 invalid/failed calls while the test compares
its complete `/proc/PID/fd` map between phases.

The test-only interposer checks `FD_CLOEXEC` at each production `sendto`, then
forks and execs a child to assert the descriptor disappeared. It exercises the
SOCK_CLOEXEC EINVAL fallback, interrupted send retry, socket/setup/send errors,
and a short send. Repeated injected failures under a 32-descriptor limit must
still allow successful delivery after injection is removed. Interception is
only for these safety/error checks; ordinary integration and timed delivery
use real AF_UNIX socket syscalls. An instrumented shared object built from the
same production source runs the integration cases with ASan/UBSan separately.

Build and correctness commands (run from the repository root):

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include bashlogger --name sol-bashlogger
python3 tests/sol-bashlogger-socket.py out/bash-sol-bashlogger
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  bash tests/sol-bashlogger-build-fixtures.sh "$EVIDENCE/fixtures"
python3 tests/sol-bashlogger-socket.py out/bash-sol-bashlogger \
  --shim "$EVIDENCE/fixtures/syscalls.so"
python3 tests/sol-bashlogger-socket.py out/bash-sol-bashlogger \
  --module "$EVIDENCE/fixtures/bashlogger-sanitize.so" \
  --asan-runtime "$(cat "$EVIDENCE/fixtures/libasan.path")"
```

`CAMPAIGN` denotes the campaign directory and `EVIDENCE` the task's private
output directory. The fixture builder compiles only; Python tests do not
invoke compilers. No companion loadables or shared-helper changes are needed.
`config/helpers.json` has no command-specific entry for bashlogger; the build
selection adds the standard `_jsmn` staging helper and no libraries.

## Measurement

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-bashlogger.py --binary out/bash-sol-bashlogger \
  --count 5000 --runs 9 --output "$EVIDENCE/benchmark.json"
```

The fixed work unit is 5000 messages, each with priority `local0.info`, tag
`bench`, and arguments `record INDEX payload-0123456789abcdef`, INDEX from 0
through 4999. The independent receiver expects each exact datagram
`<134> bench: record INDEX payload-0123456789abcdef`, in order, without extra
messages. Every pass requires all bytes/counts, zero stderr, the expected
sender count and status 0. One warm-up precedes nine measured samples. Each
pass resets the shell and private socket. The ready sender is released after
startup; timing includes delivery, the shell loop, Python receiver validation,
and sender teardown. Sender and receiver share one fixed CPU. This is API wall
time with no external ratio. The report records all pass statuses, sample
distribution, work/fixture hashes, source/binary/harness hashes and versions.

Validation on 2026-10-19 passed 611 ordinary checks and the same 611 checks
with ASan/UBSan (instrumented production module). The interposed run passed
622 checks, including 1196 live-descriptor CLOEXEC/exec observations. The
starting binary failed 373 assertions before its persistent-shell test aborted;
that run is retained as regression evidence, not used as a timing baseline.

The gated 2026-10-19 measurement passed all ten passes (one warm-up and nine
samples): 50,000 datagrams checked, with 243,890 received bytes per pass.
On CPU 11 of an Intel Core i7-9850H, Linux 6.12.111, GCC 14.2.0, Bash 5.3.15,
the median was **143.096 ms per 5000 messages** (34,942 messages/s). Samples
ranged from 127.366 to 154.202 ms; sample standard deviation was 8.311 ms.
These are wall times for this API workload on a shared host, including the
Python receiver. There is no speedup claim or matched external baseline.

Measured source SHA-256:
`37cc001430e39308cfe7c1987e946c9a55d9ba4e59c430840f9c4d2aa79653c6`.
Measured binary SHA-256:
`e333d84e996d74fedd316f459c954dbdc27836110314d00e20582b0622709a0f`.

No host syslog daemon, disk persistence, RFC timestamp/hostname formatting,
network transport, or external logger performance is qualified by this task.
Raw logs and benchmark reports live in the task evidence directory; historical
benchmark/catalog files remain untouched.
