# payload — installer contract, fixture and measurements

`payload` (`loadables/payload.c`) is the bashy.box front-end for the native
payload share. `list`, `installed` and `info` read the share INDEX and the
install state in-process. `install` and `remove` hand off to an external
installer, `bl-pkg.sh`.

## The external helper and who owns it

`bl-pkg.sh` is **not part of this repository**. The bashy.box image ships it at
`/bash-os/bl-pkg.sh`, and the image also owns the payload share (default
`/root/loadables`) and the state it records under
`ROOT/var/lib/bl-pkg/installed/NAME`. This repository owns only the argv that
`payload` sends across that boundary, the checks it makes before sending it,
and how it reads the results back. No copy of the helper exists on the
development host. The integration fixture therefore pins the boundary with a
recording fake that receives exactly the production argv.

### Configuration

Each call resolves these values once and keeps its own copy of each:

| value | source, first match wins | default |
|---|---|---|
| repo | `PAYLOAD_REPO`; then `BASHPKG_LOADABLES_DATADIR` (environment, then shell variable) | `/root/loadables` |
| root | `PAYLOAD_ROOT` | `/` |
| installer | `PAYLOAD_INSTALLER` | `/bash-os/bl-pkg.sh` |
| interpreter | `$BASH` (environment, then shell variable) | `bash` looked up in `PATH` |

### Argv contract

```
$BASH INSTALLER --internal --root ROOT --repo REPO --allow-unsigned install NAME...
$BASH INSTALLER --internal --root ROOT rollback TXN
```

* Each value above is passed as a single argv element. No shell parses it, so
  spaces, quotes and `$(...)` in paths reach the helper unchanged.
* The helper is run by the interpreter, so it must be a **readable regular
  file**; it does not need execute permission (the image ships it with mode
  0644). If it is missing, `payload` exits 127. If it is a directory or
  unreadable, `payload` exits 126. In either case the helper is not started.
* `install` runs the helper **once** for all NAMEs, and only after every NAME
  passes two checks:
  * it matches `[A-Za-z0-9][A-Za-z0-9._+-]*` and is shorter than 256 bytes, so
    it can be neither an option nor a path;
  * it has an INDEX record.

  If any NAME fails, the helper is not run. An invalid NAME exits 2. A NAME
  with no record is reported and exits 1.
* `remove` runs the helper once per NAME. It takes `TXN` from the first
  `txn=` line of `ROOT/var/lib/bl-pkg/installed/NAME`. A NAME is refused (and
  the helper is not run for it) if:
  * the NAME is invalid;
  * the NAME is not installed;
  * the state file has no `txn=` line;
  * the TXN is empty, starts with `-`, contains a space or control byte, or is
    256 bytes or longer;
  * the `txn=` line is longer than 8191 bytes.

  The remaining NAMEs are still processed. After a successful rollback,
  `payload` prints `payload: removed NAME`. Standard output is flushed before
  every fork, so this line always follows the helper's own output.
* The helper inherits the shell's exported variables, including one-command
  assignments such as `FOO=1 payload install x`. Its signal dispositions are
  reset to their originals, and job control is off in the child. `payload`
  waits for its own child only, with SIGCHLD briefly set to default, so the
  shell's background-job statuses are not lost.

### Exit status

| case | status |
|---|---|
| success | 0 |
| usage error or invalid NAME (`install`, `info`) | 2 |
| installer missing / not a regular file or unreadable | 127 / 126 |
| interpreter cannot be executed | 127 (ENOENT) or 126 |
| helper exited N | N (`install`); for `remove`, the first failing helper status |
| helper killed by signal S | 128+S |
| missing package, NAME refused by `remove`, unreadable INDEX, write error | 1 |

### Trust model

The share is a **trusted local repository** staged by the host. `payload`
always passes `--allow-unsigned`; it does no signature checking of its own.
`pkg` is the command for the signed-mirror workflow. `payload` does not trust
the share's *structure*, however. INDEX records with an embedded NUL, an invalid name, a field
of 256 bytes or more, no `name=`, or a line longer than 8191 bytes are skipped.
`list` and `info` report the number skipped on stderr, and `install` will not
act on a skipped record. Previously, the 8 KiB tail of an overlong line could
be read as a record of its own. Unreadable INDEX files, such as a directory
named INDEX, fail with status 1.

## Defects fixed

1. **Shared getenv buffer (use-after-free).** With one-command assignments,
   `PAYLOAD_ROOT=/r PAYLOAD_REPO=/p PAYLOAD_INSTALLER=/i payload install x`
   built argv from pointers into one shared buffer that bash frees on the next
   `getenv`. As a result, the helper received the repo path where the
   installer belonged, or freed bytes. Values are now copied once per call.
2. **Option and path injection.** NAMEs such as `--root=/`, `-x`, `../etc`,
   `a b` and an empty string reached the helper's argv, and `remove` opened
   `ROOT/var/lib/bl-pkg/installed/../../..`. A `txn=--root=/` state line was
   passed straight to `rollback`. Names and TXNs are now validated.
3. **Missing packages.** `install a nope` ran the helper anyway. It now checks
   every NAME against the INDEX first and installs nothing if any is missing.
4. **Exit propagation.** Every helper failure, including a missing helper and a
   signal, was reported as 1. The helper's status (or 126/127, or 128+S) now
   becomes `$?`.
5. **Unsafe child handling.** The old fork/exec left bash's SIGCHLD handler
   active, so the shell could reap the helper first, and `waitpid` then read an
   uninitialised status. Pinned to one CPU with output on a pipe, a successful
   install was reported as `bl-pkg exit -1`. The child also inherited trap and job-control state.
   It now uses the shared `child-wait.h` and `command-run.h` helpers, as `nice`
   and `env` do. The child's environment is bash's export environment, so
   one-command assignments reach the helper.
6. **Output ordering and write errors.** `payload remove a b` piped to a file
   printed `removed a` after the helper's output for `b`. `payload list
   >/dev/full` exited 0. Standard output is now flushed before each fork, and
   write errors return 1 with a message.
7. **Malformed INDEX and state** as described above. `info` and `installed`
   also reject extra arguments, and `payload help` now prints the full help
   text to stdout instead of a one-line usage error.
8. **Per-record state probes** built and `stat`ed `ROOT/var/lib/bl-pkg/installed/NAME`
   by full path for every record. They now use `fstatat` against one directory
   descriptor that is opened once per call and closed afterwards.

## Fixture

`tests/opus-payload-installer.py BINARY` runs without compiling anything, with
an empty `PATH`. It uses a private repo whose name contains spaces, quotes and
`$(touch PWNED)`, a private root, and a fake `bl-pkg.sh` with mode 0644. The
fake records `$BASH`, `$0` and `"$@"`, and keeps its own install state. It
covers:

* `list`, `installed`, `info`, `--porcelain`, `--available`, filters and the
  repo fallback order;
* install of several names, missing names and invalid or injection names;
* malformed INDEX and state files;
* helper absent, a directory, unreadable, non-executable, exiting 1/3/42/255,
  or killed by SIGTERM; and an interpreter that cannot be executed;
* rollback by the TXN the helper wrote, in a full install → list → remove
  round trip;
* partial and failing `remove`;
* background-job status across the helper wait;
* 25 repeated mixed calls in one shell with a descriptor-count check;
* `/dev/full` output, and stdout reuse afterwards.

`tests/opus-payload-build-sanitizer.sh OUT` builds `payload.c` as an
ASan/UBSan module (through the build gate). Passing `--module
OUT/payload-sanitize.so --asan-runtime "$(cat OUT/libasan.path)"` runs the
same checks against it.

The fixture never touches `/root/loadables`, `/var/lib/bl-pkg` or
`/bash-os`. The real `bl-pkg.sh` has not been qualified against this argv
here, because it is not available on this host. That check belongs to the
bashy.box image.

## Measurements

These historical timings predate the bounded line-reader correction for embedded
NUL bytes. They do not measure the corrected parser or establish its speedup.

All timings are self-timed on one host (i7-9850H, Linux 6.12), pinned to CPU
2 and run through the campaign bench gate. There is no external comparator: no
other program implements `payload`, so no ratio is given. Both binaries were
built by `./build.sh --include payload` from the same commit. They differ only
in `loadables/payload.c`:

| binary | `payload.c` | binary SHA-256 |
|---|---|---|
| baseline | original | `d8e82b90…` |
| fixed | SHA-256 `44f03229…` | `ccc6e573…` |

**Parsed inventory** uses the unchanged `bench/loadables.py` case
`payload-list`. One pass streams a 1,696,256-byte INDEX of 20,000 records with
2,500 installed, and prints 20,005 lines. Each sample is 40 passes, and every
pass's output was validated. The baseline and fixed binaries ran interleaved
(base, fixed, base, fixed) under one gate slot; medians of 7 samples, in ms:

| round | baseline | fixed |
|---|---|---|
| 1 | 1915 (1788–2000) | 1675 (1605–1769) |
| 2 | 2036 (1829–2454) | 1766 (1506–1903) |

The fixed medians are 12.5% and 13.3% lower. Their output is byte-identical to
the baseline's for `list`, `list -p`, `installed`, `list --available` and
`info`. The saving comes from the per-record probe: one `fstatat` against an
open directory descriptor replaces an `snprintf` and a full-path `stat` (and,
when the root came from a one-command assignment, a `getenv` copy) for every
record. Load on this shared host varied (1-minute load average 2.7–3.8 at
round start), so the figures are same-session evidence only, not a
cross-build benchmark.

**Helper transactions** (`bench/opus-payload.py`): one sample is 20 ×
(`payload install` + `payload remove`) of the last record of a 2,000-record
INDEX. That is 40 helper fork/exec round trips through the fake `bl-pkg.sh`,
20 full INDEX scans and 20 txn lookups. Every sample, the warm-up included, is
checked for exact stdout, exit status, all 40 recorded argv vectors and an
empty final state. The fixed binary passed on every sample, with medians of
126.6 ms and 111.0 ms over two rounds (range 105.9–141.1). Almost all of that
time is the helper processes themselves. The **baseline produced no valid
transaction sample**: pinned to one CPU with its output on a pipe, its first
`payload install` reported `bl-pkg exit -1` and returned 1 even though the
helper had installed the payload. That is defect 5: the shell reaped the
helper before `payload` waited for it. `tests/opus-payload-installer.py` now
includes this case, named "helper reaped by payload, not the shell, on one
CPU".
