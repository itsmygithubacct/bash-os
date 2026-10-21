# doas credential and policy boundary validation

`doas` and `sudo` share `loadables/doas.c`. Non-root policy and authentication
belong to `/dev/bashos-auth`; without that authority the frontend delegates to
an external doas executable. Root runs a forked credential drop. These are
separate execution paths and must be tested separately.

This change makes the root path honor explicit runas groups, includes the
primary group with supplementary memberships, and when that list already
fills all 64 slots still keeps the passwd primary group and an explicit `-g`
group by dropping a non-required membership. It captures caller IDs before the
drop for `SUDO_UID/GID`, rejects overflowing numeric target IDs and malformed numeric groups, propagates wait errors,
and fails closed on unknown or mode-inconsistent authority decisions and
approvals. A successful verifier launch no longer masks a denied or failed
reauthorization. On the shared interactive authority loop, a verification
status byte other than `V` fails closed for doas and sudo; EOF still returns
the child's command status. An internal negative availability sentinel keeps an interactive
policy denial (exit 125) from triggering external fallback. Help/version
writes report output errors and recover on the next call. Child descriptor
cleanup first uses Linux `close_range`, retaining the loop for unavailable or
filtered syscalls. The shared sudoedit helper closes its staging descriptor
following a successful rename.

All five raw-fork paths now use the existing `child-wait.h` guard until the
owned child has been waited for. This prevents Bash's SIGCHLD handler from
stealing fast-child exit statuses, while restoring the child's previous mask
and the parent's handler and mask. The native regression runs 1,000 pinned
rounds through both doas and sudo, checking unrelated background-job statuses
and the shell's CHLD trap.

`tests/sol-doas-fixture.c` includes the actual production source and shared
credential helper. Compile-time function substitutions inject account streams,
credential syscalls and authority ioctls. The minimal generated Bash adapter
only supplies word-list/builtin types and diagnostics; parsing, dispatch,
request construction/digest, credential sequencing, environment construction,
signal/FD cleanup, fork/exec/wait, and sudoedit orchestration are production code.
There are no runtime test hooks in the shipped binary. Tests never edit real
accounts, policy, or privileges.

The fixture covers both entry points, root target/group requests, each failed
credential step and failed verification, allow/deny/auth-required policy,
invalid decisions/approvals, explicit authority group flags, reset/validation,
literal argv including empty/newline/quote/metacharacter arguments, dangerous
environment removal, caller metadata, inherited descriptor closure and the
fallback close loop, signal restoration, child status/signal propagation,
output errors and repeated calls. Owned children also perform actual
`setresuid/setresgid` to the invoking identity and execute commands. Privileged
identity changes and supplementary-group changes are intercepted.

Sudoedit tests use private temporary files and intercept production OPEN and
COPYBACK requests. They check fresh authorization handles, unchanged digest
binding, FD-vector contents, cleanup, denied/expired reauthorization, editor
failure, no-follow temp reopening, and denied/disabled copyback. Separate tests
execute the shared atomic-copyback helper on real private files: successful
replacement, bad source, owner-independent mode/link/inode drift, symlink
replacement, unchanged originals on rejection, staging-file cleanup and FD
counts. They do not qualify the kernel's protected path resolution or
multi-target partial-commit behavior.

Build the native entry points with the explicit companions:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- ./build.sh --include doas,sudo,su --name sol-doas
python3 "$CAMPAIGN/scripts/gated.py" build -- python3 tests/sol-doas-build.py "$EVIDENCE/fixture-build"
python3 tests/sol-doas-check.py --fixture "$EVIDENCE/fixture-build/fixture" --shell out/bash-sol-doas
python3 "$CAMPAIGN/scripts/gated.py" build -- python3 tests/sol-doas-build.py "$EVIDENCE/sanitize-build" --sanitize
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 tests/sol-doas-check.py --fixture "$EVIDENCE/sanitize-build/fixture"
```

`CAMPAIGN` and `EVIDENCE` identify the campaign and private evidence directories.
The native fallback checks require a non-root host without the authority device;
the mandatory standalone fixtures run in an unprivileged test process, require
neither a real target account nor an authority device, and skip no cases.
They use an owned external delegate to check native empty-PATH execution,
repeated calls, literal argv, FD cleanup and failures.

`config/helpers.json` requires both `doas` and `sudo` in the build selection.
They pull `_bashauth`, `_mbedtls`, `_bashos_authcrypto`, and `_monocypher`.
`su` additionally exercises the sibling entry point. Existing
`tests/final-smoke.py accounts` needs `login,passwd,auth,su,doas,sudo` selected;
its live root drops require an unprivileged account and root, while `su` also
requires the kernel token authority. Those conditional checks do not replace
these mandatory fixtures. Actual root drops, live policy reloads, password
verification, kernel token lineage, and authority copyback need separate
qualification on a provisioned system.

`bench/sol-doas.py` measures policy/request work, verifier-launch work, and
child execution separately. It runs one warmup and at least seven samples with
fixed work counts, checking every pass's status and each batch's exact output.
It records affinity, versions, hashes, distributions and reset rules. Run it
through the bench gate after building fixtures. These are syscall-shim timings,
including real fork/exec/wait where applicable; they are not authentication
hashing or live kernel-policy timings, and have no external-tool ratio.

The validation run on 2026-10-19 passed all four mandatory fixture groups under
ASan/UBSan: 933 parent assertions plus checked child assertions, with no skipped
fixtures. A separately compiled historical-source fixture fails all four
regression groups as expected. Its policy, verifier-launch and owned-child
measurement workloads independently pass their output/status oracles before
any paired timing. Native entry and fallback checks run separately from these
injected credential and authority paths.

The following historical measurement predates the raw-child wait correction;
it does not measure corrected code. The validated measurement used CPU 11, one warmup and seven samples of 16 work
units per phase and variant. Median batch time divided by 16 was:

| Phase | Baseline | Current |
|---|---:|---:|
| Policy request/authorization shim | 0.104 ms | 0.164 ms |
| Verifier launch/wait shim | 0.272 ms | 0.255 ms |
| Owned child transition/exec | 84.7 ms | 0.858 ms |

The equivalent owned-child baseline was 84.7 ms. A separate syscall profile
recorded 524,285 failed `close` calls in its cleanup loop; the replacement uses
one `close_range` call. Both variants validated the same owned identity,
group request, environment fields, descriptor closure and `/bin/true` status.
Policy and verifier-launch results include process startup and assertion costs;
no speedup is claimed for those phases. These figures qualify the standalone
syscall-boundary fixture only, with no external ratio or live-authority timing.
The raw campaign report retains all sample distributions, source/binary hashes,
build commands, versions, affinity and reset rules.
