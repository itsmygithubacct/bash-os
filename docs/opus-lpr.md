# lpr: spool and deliver to a configured backend

`lpr` used to copy a file into a spool and then sleep, which it reported as a
finished print. It now hands every job to a backend executable you name, and
reports a job as accepted only when that backend accepts it. If no backend is
configured, `lpr` refuses the job.

## Configuration

| variable | meaning |
|---|---|
| `BASHLPR_BACKEND` | Absolute path of the backend executable. Required. If it is unset or empty, `submit` fails with status 1, and nothing is spooled or delivered. A relative path, a missing file, a directory or a non-executable file is also refused before anything is spooled. |
| `BASHLPR_SPOOL` | Spool directory (default `/var/spool/lpd`). It is created with mode 0700. The directory must be a real directory, not a symlink. It must be owned by the effective uid and must not be writable by group or other. If it does not meet these rules, `submit` and `cancel` refuse to use it. |
| `BASHLPR_TIMEOUT` | Seconds a backend may run before the job fails. `0` (the default) means no limit. The maximum is 86400. Any other value is a usage error. |

`BASHLPR_PRINT_SEC` (the old sleep length) no longer has any effect.

## Backend contract

`lpr submit FILE` (or `-` for stdin) first copies the input to
`$BASHLPR_SPOOL/<id>.lpr` (mode 0600). `<id>` is 16 random hex digits. `lpr`
then runs the backend as its own child, with this literal argv:

    $BASHLPR_BACKEND <id> <bytes> <title>

The child is started without a shell and without a PATH search. `<title>` is
the input's basename, or `stdin` when the input is `-`. The spool entry is the
backend's stdin, opened read-only and seekable. stdout and stderr are the
caller's. Every other descriptor is closed on exec. The environment is the
shell's exported environment.

A network protocol, such as RFC 1179 LPD or IPP, belongs in the backend. It
is an executable like any other.

## Observable states

| state | how it is reported | exit status |
|---|---|---|
| spooled | stdout `lpr: spooled <spool>/<id>.lpr` | — |
| accepted | stdout `lpr: accepted <id> (<n> bytes)`. The backend must exit 0 **and** its stdin offset must have reached `<n>`, which shows it consumed every byte. | 0 |
| failed | stderr `lpr: failed <id>: <reason>`. The reason is one of: nonzero exit, killed by a signal, exited 0 without reading every byte, timed out, or could not exec. Spool errors (unreadable input, a write error such as `EFBIG`/`ENOSPC`, an unusable spool) are reported as `lpr: submit: ...`. | 1 |
| cancelled | stderr `lpr: cancelled <id> — cleaned spool <path>` | 3 |
| interrupted | SIGTERM, SIGINT or SIGHUP reached the submitting shell. stderr shows `lpr: interrupted by signal N — cleaned spool <path>`. The signal is then passed to the shell's own handler: an untrapped SIGTERM still terminates the shell, and a trap runs. | 128+N |

Every outcome removes the spool entry and its control FIFO. If `stdout` cannot
be written, the job is withdrawn before the backend runs.

`lpr list` keeps its v1 output, one `<spool>/<id>.lpr` line per entry. A
missing spool directory produces an empty list. `lpr list -l` prints
`<id> active|stale <bytes>` for each entry.

## Cancellation and process identity

Each job holds the read end of `$BASHLPR_SPOOL/<id>.ctl`, a FIFO, for its whole
life. `lpr cancel <id>` opens that FIFO for writing with `O_NONBLOCK|O_NOFOLLOW`
and checks that it is a FIFO. It then writes one byte and waits, for at most
10 s, until the submitter closes its end. The submitter closes its end only
after it has reaped the backend and removed the spool entry.

Two processes take part in a cancellation, and they have different jobs:

* `cancel` never sends a signal to anything.
* The submitter signals only the backend child it forked. While SIGCHLD stays
  blocked and the child is still unreaped, its pid cannot be recycled. The
  signal is sent through a `pidfd_open` descriptor; `kill` is the fallback.
  The child first gets SIGTERM, and SIGKILL after a 2 s grace period.

If the open fails with `ENXIO`, nothing has the FIFO open for reading, so no
live submitter owns the job. The same applies when the `.ctl` file is missing
or is not a FIFO: the job is **stale**. `cancel` removes its `.lpr`, `.ctl`
and any old `.lpr.pid` sidecar, and says that nothing was signalled. PID files
are never read, so forged or stale PID metadata cannot direct a signal. A
`.ctl` that is a symlink is refused (`ELOOP`) and not followed.

If the backend has already exited when the cancel request arrives, its result
stands. A backend that exited 0 after reading everything is accepted, even if
`cancel` ran at the same moment. The race test checks that in every iteration
the outcome matches what the backend recorded.

## Tests

`tests/opus-lpr-delivery.py BINARY` (26 tests, about 10 s). All of them run
with an empty `PATH`, a private temporary spool and a fixture backend that
records its argv, the bytes it received, its stdin mode, its descriptors and
the signals it caught. They cover:

* Success on a private spool: exact bytes, literal argv including shell
  metacharacters in the title, spool mode 0700 and job mode 0600, an empty
  spool afterwards.
* Submission from stdin; exported variables reach the backend and unexported
  ones do not; the caller's descriptor 7 is not inherited.
* Backend failures: exit 3, SIGSEGV, partial consumption, timeout. A missing,
  empty, relative, directory or non-executable backend spools nothing; an exec
  failure is withdrawn.
* A group/other-writable spool and a symlinked spool are refused.
* Partial input: an unreadable or missing source; an `EFBIG` spool write
  (`ulimit -f`); SIGTERM, or `cancel`, while stdin has only delivered part of
  the job.
* Cancellation: a listed active job; a backend that ignores SIGTERM and is
  killed after the grace period; SIGTERM to the submitting shell, both
  untrapped and trapped; 24 cancel/completion races.
* Stale or forged metadata: a `.lpr.pid` naming a live process that belongs
  to the test, a regular-file or reader-less FIFO `.ctl`, and a `.ctl`
  symlinked to an outside FIFO. In each case the victim survives and the
  outside FIFO receives no bytes. A shell killed with SIGKILL leaves a stale
  job; `cancel` removes it and leaves the orphaned backend alone.
* Invalid ids.
* Repeated submissions in one shell: unique ids; descriptor count, blocked,
  caught and ignored signal masks and traps unchanged; a background job's
  status is still collected by `wait`.
* Output to `/dev/full`; `list` keeps its v1 format.

`tests/opus-lpr-sanitize.sh BINARY` builds `lpr.c` as an ASan+UBSan module and
runs the same suite against it. It compiles, so it must run through the
campaign build gate.

## Benchmark

`bench/opus-lpr.py --binary out/bash-... --cpu N --output report.json`.
Each sample is one shell that submits an 8 MiB seeded random fixture 16 times.
The backend is `exec /usr/bin/sha256sum`. Every pass is checked against a
digest the harness computes itself: 16 `accepted` lines with the right byte
count, 16 backend digests and an empty spool. The reference does the same byte
work in the same shell with `cp`, the same backend and `rm`, but without
spool-privacy checks or a cancellation channel. The figure measures spool and
local delivery overhead, not printer throughput.
