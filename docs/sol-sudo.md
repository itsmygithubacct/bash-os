# sudo front-end validation

`sudo` is the sudo-shaped entry point to `loadables/doas.c`. Non-root callers
go through `/dev/bashos-auth` when it advertises the v2 authority, and
otherwise through an external doas. Root callers fork, drop credentials and
exec. `docs/sol-doas.md` covers the shared backend; this document covers what
is specific to sudo and the independent revalidation of that backend.

## Behavior changes

Options now parse like sudo(8), which uses `getopt_long` with a leading `+`:

- short options bundle (`-iu bob`, `-nk`), and `-u`/`-g` take an attached or
  following argument (`-ubob`, `-u bob`, `--user=bob`);
- parsing stops at the first operand, and `VAR=value` words directly before
  the command become its environment (a later `-n` is a command, as in sudo);
- one-letter names such as `A=1` are assignments; before, they were run as the
  command;
- only one of `-e`, `-i`, `-K`, `-l`, `-s` and `-v` may be given; before,
  combinations such as `-v -e FILE` silently did only one thing;
- `-K` and `-v` refuse a command, and assignments without a command are a usage
  error;
- unlisted options, including inside a bundle (`-nE`) and abbreviated long
  options, are still refused.

`sudo -k COMMAND` used to perform only the reset and return 0 without running
the command. It now sends a `RESET_TIMESTAMP` request and then authorizes
and runs the command; if the reset fails, nothing runs. `-g GROUP` without
`-u` runs as the invoking user, as in sudo, instead of as root.

On the interactive authority route, a request that the policy still answers
"authentication required" after one successful verification used to return 0,
although the command had not run. It now fails with status 1. A read error on
the one-byte verification marker also fails closed (status 1) after the child
is reaped and the parent's signals are restored; `EINTR` is retried. EOF still
means the child was not verify-only. A child that cannot write the marker
exits 125 and does not call the verifier.

On the root route:

- `-i` changes to the target's home before starting the shell; a missing home
  is reported and the shell starts where it is. The shell is named `-` plus
  its basename (it used to be `-bash` for every shell).
- The group vector keeps the target account's passwd primary group when `-g`
  selects another primary group, as sudo's runas group list does. Before, that
  group was dropped. A membership list that already fills all 64 slots still
  keeps that passwd group and the selected `-g` group, dropping a non-required
  membership instead. If the required groups themselves do not fit, the child
  exits 126.
- `SUDO_USER` names the invoking account from the account database, not the
  caller's `$USER`.
- `SUDO_COMMAND` is exported for sudo (not for doas). Its argument text is
  truncated at 4096 bytes, as in sudo(8), so the diagnostic value cannot by
  itself make `execve` fail with `E2BIG`. The argv passed to `execve` is not
  truncated. An explicit `SUDO_COMMAND=` assignment is kept as given.
- A command-line assignment replaces an earlier value of the same name, so the
  child never sees duplicates. As in sudo, assignments are applied after
  sudo's own variables. Dangerous names are still removed.

sudoedit splits `SUDO_EDITOR`/`VISUAL`/`EDITOR` into words at blanks without
shell parsing, as sudo does, so `SUDO_EDITOR="vi -n"` works; a blank variable
falls through to the next one.

Without the authority, an explicit `BASHSUDO_EXTERNAL` (then
`BASHDOAS_EXTERNAL`) delegate still receives the original words. The default
external `doas` now gets doas syntax: `-n`, `-u USER`, `-s`, `--` and the
command, or `-L` for `-k`/`-K`. Requests doas cannot express (`-i`, `-e`,
`-v`, `-g`, `VAR=value`, `-k COMMAND`, `-s COMMAND`) are refused with status 1
instead of being handed to doas to misread.

Bash refreshes the C `environ` only when it next runs an external command.
The external delegate and the sudoedit editor were started with a raw
`execvp`, so right after `export PATH=...` they were looked up on the old
`PATH` and given the old environment. The child now refreshes the exported
environment first, as `ns` does.

The changes that also affect doas (interactive fail-closed, `SUDO_USER`, group
vector, current exports) are separate commits. `tests/sol-doas-fixture.c` changed one expected
value, the group vector, to match.

## Tests

`tests/sol-sudo-fixture.c` includes the production `doas.c`, `sudo.c`, the
credential helper and the shared sudoedit helper verbatim. Compile-time
substitutions point `/etc/passwd` and `/etc/group` at private files read by
the production parsers. They also intercept credential syscalls on the
injected root route, emulate the authority device, set `isatty`, and capture
`execve`/`execvp` before (optionally) really executing. Every authority request is
recorded in shared memory, including those made by forked production
children, and the parent checks them. Replies are scripted per call. The
groups are:

- `options`: bundles, attached and long forms, `#uid`, exclusive modes,
  refused options, assignment placement, literal argv, help/version output
  failures. Usage errors make no request and start no child on either route.
- `lookup`: malformed and overflowing account rows, group names that are
  prefixes of other names, malformed and out-of-range gids, `-g` without `-u`.
- `authority`: request fields, argv and environment blobs, handle use,
  O_CLOEXEC on the device descriptor, and descriptor counts across repeated
  calls. It also covers allow, deny (with the audit diagnostic),
  missing-handle and mismatched decisions; non-interactive denial (`-n`, no
  terminal, or both) never starting the verifier; the interactive route with
  verification, digest binding and status, failed verification, and repeated
  "authentication required"; `-v`, `-k`, `-K`, `-k COMMAND`, `-kv` and `-k -i`;
  and explicit delegates.
- `translation`: the default doas delegate's argv and the refusals.
- `root`: credential order and values, group vectors, environment (scrubbing,
  replacement, `SUDO_*`), no_new_privs, signal mask and dispositions, closed
  descriptors, `-i`/`-s` argv, directory and `SUDO_COMMAND`, a missing home,
  each failed credential step, real exec statuses (exit, signal, not found,
  not executable, literal argv), and root sudoedit with a split editor.
- `edit`: sudoedit through the authority on real private files. OPEN uses the
  shared `bashos_sudoedit_safe_open` and makes real temporary copies; a real
  `/bin/sh` editor runs once on every copy as the caller; COPYBACK checks the
  fresh handle, the unchanged digest and read-only descriptors with the edited
  bytes, then runs the shared `bashos_sudoedit_atomic_copyback` over the
  originals. Rejections leave both originals intact and the copies removed:
  malformed OPEN replies, the gate being off, editor failure, policy drift,
  expiry without a terminal, failed re-verification, a missing fresh handle,
  the wrong decision, a copy swapped for a symlink, and an original replaced,
  hard-linked, symlinked or re-moded during the edit. Also covered: expiry
  with a terminal re-verifying once and committing; the partial multi-target
  commit (the first target committed, the second rejected); 16 targets;
  rejected 0/17/relative targets; editor selection.
- `helper`: `bashos_sudoedit_safe_open` rejections (symlink, hard link,
  setuid, setgid, FIFO, directory, missing, empty) and the ordered
  `bashos_sudoedit_run` with success, a missing editor, policy drift after the
  edit, a missing token and identity drift.

`tests/sol-sudo-check.py --fixture` runs every group in a fresh directory,
requires exit 0, the group's assertion line and no leftovers. It then checks
an independent request-digest oracle: the expected argv/environment bytes and
the wire format are spelled out in Python and hashed separately. With
`--shell`, it checks the native builtins with an empty `PATH`, usage errors
with no delegate started, verbatim explicit delegates with closed
descriptors, translated default delegates and refusals, output failures and
recovery, and 300 CPU-pinned rounds that keep background-job statuses and the
CHLD trap.

`tests/sol-sudo-userns.py --shell` runs the native shell's real root route as
root in a private user and mount namespace. The caller's subordinate id range
is mapped in, and private passwd, group and profile files are bind-mounted
over `/etc` inside that namespace only. Real `setgroups`, `setresgid`,
`setresuid`, no_new_privs, closing, exec and wait are checked through `id`,
`env` and `/proc/self/status` in the child. A target whose id the kernel
refuses fails closed with 126. With `--final-smoke`, it also runs
`tests/final-smoke.py accounts` with `BASHOS_REQUIRE_ROOT_TRANSITIONS=1`, so
its root doas/sudo transitions run instead of being skipped. Nothing on the
host changes.

A historical-source fixture built from the starting `doas.c` fails six of the
seven groups at the behaviors changed here. `helper` passes because it tests
the unchanged shared library. A native shell built before the export fix
fails exactly the six native cases and one namespace case that depend on it.

The final run passed 2537 fixture assertions in seven groups (also under
ASan/UBSan with leak detection), the digest oracle, 30 native cases, and 25
namespace cases. The namespace cases include `final-smoke.py accounts` (29
checks) with root transitions required. Its `su` transition still reports
SKIP because it needs the kernel token authority.

## Build and run

```sh
G=$CAMPAIGN/scripts/gated.py
python3 $G build -- python3 tests/sol-sudo-build.py $EVIDENCE/sudo-build
python3 $G build -- python3 tests/sol-sudo-build.py $EVIDENCE/sudo-sanitize --sanitize
python3 $G build -- ./build.sh --include login,passwd,auth,su,doas,sudo --name sol-sudo
python3 tests/sol-sudo-check.py --fixture $EVIDENCE/sudo-build/fixture --shell out/bash-sol-sudo
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/sol-sudo-check.py --fixture $EVIDENCE/sudo-sanitize/fixture
python3 tests/sol-sudo-userns.py --shell out/bash-sol-sudo --final-smoke
python3 $G bench -- python3 bench/sol-sudo.py --binary $EVIDENCE/sudo-build/fixture --output $EVIDENCE/bench.json
```

`config/helpers.json` already pairs `sudo` with `doas`. Both pull
`_bashauth` and `_mbedtls`. `final-smoke.py accounts` additionally needs
`login`, `passwd`, `auth` and `su` in the build.

## Measurements

`bench/sol-sudo.py` times five validated work units in fresh fixture
processes pinned to one CPU, with a warm-up and seven samples each. Every
unit checks its status and recorded requests, and a sample counts only if its
output is exactly `validated PHASE N` and the scratch directory is empty. The
units are:

- a policy request;
- `-k` followed by a command;
- the interactive verify route;
- a two-file sudoedit cycle with a real editor and copyback;
- a root-route child with a real exec.

These are syscall-shim timings of production code. No live policy, timestamp,
verifier or password hashing is involved, and there is no external sudo
ratio. Only `verify` and `edit` also validate on the historical source, so
only they have a paired baseline.

The 2026-10-20 run on CPU 11 used 16 units per sample (load average 8–18 on a
shared host). Median sample time divided by 16:

| Unit | Current | Historical source |
|---|---:|---:|
| Policy request and handoff | 0.518 ms | does not validate |
| `-k` then a command | 0.549 ms | does not validate |
| Interactive verify route | 1.318 ms | 1.342 ms |
| Two-file sudoedit cycle | 4.658 ms | 4.910 ms |
| Root-route child and exec | 2.115 ms | does not validate |

The paired differences lie inside overlapping sample ranges, so no speed
change is claimed. `perf` is unavailable to unprivileged users on this host.
An `strace -c` profile of 16 units per phase shows that the production code
makes one `clone`, one `close_range`, one `execve` and one `wait4` per child.
The policy routes make no forks. The remaining calls, including about a
thousand failed `fcntl` per child, are the fixture's own descriptor census.
`wait4` time is the child running. No production bottleneck remained to fix.

## Limits

- No live `/dev/bashos-auth` is available. Policy decisions, timestamps,
  the `auth-verify` verifier, password checks, the kernel's safe-open and
  copyback mediation, and the interactive in-kernel exec are emulated. Their
  real behavior, including the protected path resolution, owner handling
  for root-owned originals and the `sudoedit_live` gate, needs a provisioned
  bash-os kernel.
- The root route is exercised as namespace root over mapped ids. That uses
  the real syscalls and kernel checks, but not host root, a real account
  database or a setuid entry path.
- `sudo -l` remains a usage error that names a `/bash-os/sudo.sh` wrapper,
  which is not in this repository. The authority's `POLICY_INFO` exposes
  policy metadata only, with no rule projection to render.
- sudoedit copies back unchanged files: the copyback is one digest-bound
  request for every target, and skipping unchanged targets would need kernel
  support. The cross-target rename is not atomic (see above).
- Through the authority, `-i COMMAND` passes the command to the kernel
  unresolved and unwrapped; `-s` on the root route uses the target's shell,
  not the caller's `$SHELL`.
