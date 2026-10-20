# su software-path coverage and qualification

The command now authenticates and changes credentials in an owned child. The
calling shell retains its IDs, descriptors, directory, dumpability and SIGCHLD
handling, including when a credential syscall partially succeeds. The parent
returns the child's exit status or `128 + signal`. It also retains a terminal
snapshot while the password child runs, so cancellation restores echo.

Login mode uses the target shell's basename with a leading `-`, including with
`-c`, and changes to the target home (falling back to `/`). `--no-login` retains
the caller's directory. Both modes use the existing shared environment filter;
`--keep-env` still strips dangerous startup variables and preserves synthesized
target identity and PATH. Before exec, su closes inherited descriptors using
`close_range`, with `/proc/self/fd` enumeration as its fallback. Failure to
establish that fallback denies execution. Help reports write failures and clears
its stream error before a later invocation. The command wipes its PHC copy on
both verification and password-read failure.

The changes are limited to `loadables/su.c`. Shared account, credential,
authentication and child-wait helpers retain the preceding doas changes.

## Reproduction

Builds and timings must use the campaign's build and bench resource gates.
These are the commands **inside** those gates; correctness drivers do not compile:

```sh
python3 tests/sol-su-build.py OUTPUT/fixture
python3 tests/sol-su-build.py OUTPUT/sanitize --sanitize
./build.sh --include su,doas,sudo,login,passwd,auth --name sol-su
python3 tests/sol-su-check.py --fixture OUTPUT/fixture/fixture --shell out/bash-sol-su --oracle
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/sol-su-check.py --fixture OUTPUT/sanitize/fixture --oracle
python3 tests/final-smoke.py out/bash-sol-su accounts
python3 bench/sol-su.py --binary OUTPUT/fixture/fixture --runs 7 --passes 32 --output OUTPUT/timings.json
```

`--oracle` requires argon2-cffi, which independently checks the fixed password,
salt, Argon2id parameters and expected hash. Omit that switch only when running
additional checks after the oracle has already passed; it is part of the recorded
qualification run. `su` itself requires `_bashauth`, `_bashos_authcrypto` and
`_monocypher`; the account smoke group additionally needs login, passwd, auth,
doas and sudo. doas/sudo must be selected together, and add `_mbedtls`.

## Evidence boundaries

The standalone fixture includes the actual command and shared source files.
Account file opens, tty byte reads/termios calls, authority open/ioctl and
credential syscalls are injected at compile time. The parser, account/shadow
reader, secure mapped password buffer, real Argon2id calculation, token request
construction, group parsing, credential ordering/verification, environment
filter, fork/wait and command execution code remain production code.

Assertions cover:

- Correct/wrong passwords, locked/empty/malformed shadow entries, missing tty,
  read errors, oversized passwords, failure lockout and success cleanup.
- Independent PHC hash oracle, password zeroing before unmap, su's PHC wipe,
  and token-request wipes after successful and rejected mint/consume requests.
- Exact target UID/GID/name/purpose/expiry/token request fields, close-on-exec
  authority descriptors, and denial before execution on authority failure.
- Target supplementary groups and primary group, setgroups/setresgid/setresuid
  ordering, saved-ID verification, and denial at each failed transition step.
- Root password bypass while retaining the authority requirement; login and
  non-login argv/directory behavior; default and filtered retained environments.
- Signal reset and unmasking, descriptor cleanup including the close-range
  fallback, repeated invocation, fork failure, interrupted wait and exec errors.
- Actual owned child setresuid/setresgid to the current identity, real `/bin/sh`
  execution, status 37, signal status 143 and setup/exec failure status.
- Private PTY password reading with echo disabled and terminal restoration on
  success and SIGTERM cancellation. Native shell checks use empty PATH, output
  failures, repeated calls and unrelated background job status preservation.

The owned child workload intercepts setgroups; it does not prove that this host
can apply another user's supplementary groups or gain another identity. The
native successful password test intentionally ends in missing-authority denial.
The conditional root/authority smoke cases remain reported gaps, not passes.

**Core status is incomplete.** This host has no `/dev/bashos-auth` and runs as an
unprivileged user. Live token authorization, privileged target transitions and
kernel enforcement cannot be qualified here. No device was provisioned and no
real passwd, shadow or policy was changed. Interactive job control and signal
forwarding from a signal directed only at the waiting parent are not qualified.
Shared secure-reader failures to disable echo, failed mlock, and failure to
restore terminal settings are not covered by these fixtures; the helper retains
its existing best-effort behavior on those boundaries. Concurrent lockout writers
and more than the shared 64-group limit are also outside this coverage.

## Measurement

The task-owned benchmark records separate authentication and child batches.
Authentication performs a real Argon2id verification at 1024 KiB, one pass and one
lane, using injected tty bytes and account opens. Child execution bypasses the
password as root-route logic does, checks both token requests, applies real
setresuid/setresgid to the current owned identity, and executes `/bin/sh -c
'exit 37'`. Each pass asserts its independent expected result. These are
syscall-fixture timings with assertion/startup overhead, not live-authority or
external-su ratios. There was no validated historical su timing to reproduce and
no performance improvement is claimed. Raw distributions, affinity, versions,
fixture/source/binary hashes and exact receipts are retained with the task result.

Recorded validation passed the production-source fixture, the same fixture under
ASan/UBSan with leak detection, the native six-command Bash build, and all 27
existing account-smoke checks. The smoke group explicitly skipped root
transitions. Native tests also passed 200 repeated su calls with an unrelated
background job and CHLD trap. The cancellation assertion failed on the retained
pre-fix native binary, then passed after the parent terminal guard was added.
One earlier sanitizer build was rejected by the source-stability check because
its inputs changed during compilation; only the subsequent stable build was used.

The initial CHLD test used command substitutions to inspect traps. That pattern
also aborted the host Bash with `:` or `/bin/true` in place of su. The final test
retains the same trap and job-status assertions using builtin file snapshots;
this independent Bash defect is not represented as a su failure or fix.

Seven samples of 32 operations after one warm-up batch, pinned to CPU 11:

| Boundary | Minimum ms/op | Median ms/op | Maximum ms/op |
| --- | ---: | ---: | ---: |
| auth | 2.612 | 2.722 | 2.913 |
| child | 1.612 | 1.722 | 2.025 |

Compiler: cc (Debian 14.2.0-19) 14.2.0; libc glibc 2.41.
Fixture binary SHA-256: `12b458420ee4a75ccdeb42120b50f34b81b7e6bab8323b29897d5e364c2bbcdf`.
Each minimum/median/maximum divides a whole batch by its fixed work count;
the raw report preserves all samples. Both case statuses are `validated`.
