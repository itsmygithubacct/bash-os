# halt wrapper contract and closed-boundary checks

`halt` calls `reboot(RB_HALT_SYSTEM)` directly. `reboot` and `poweroff` use
`RB_AUTOBOOT` and `RB_POWER_OFF` through the same implementation header.
The existing Bash-OS options are preserved: `-f` skips `sync()` and `-n`
prints a dry-run message without performing any mutation, including with `-f`.
These meanings differ from other halt implementations. There is no init/runlevel
transition, permission override, or wtmp/utmp accounting. Accounting options
`-w` and `-d` are unsupported and return usage status 2 before any mutation.
An ordinary request syncs first; a forced request still reports kernel errors.

The shared-header fixes reject operands before requesting shutdown,
handle `--help` through Bash's help convention (status 2), propagate a failed
dry-run write, and return success when the reboot boundary reports success.
Kernel errors produce a diagnostic and status 1. A real successful shutdown
normally does not return; a successful fixture return is useful for exercising
the wrapper's return handling and repeated invocation in a live shell.

`tests/sol-halt-shim.c` provides closed replacements for `reboot`, `sync`,
`updwtmp`, `updwtmpx`, `pututline`, and `pututxline`; it never forwards them to
libc. A fixture builtin exposes request counts, constants and ordering.
`tests/sol-halt-check.py` executes the actual compiled production builtins with
that library preloaded. It contains 108 assertions across all three siblings,
including invalid operands/options, combined flags, help, five injected errno
values, failed output writes, recovery, empty PATH, and 200 rounds per sibling
checking shell variables, positionals, options, traps, umask, working directory,
caller-owned descriptors, and descriptor counts. Sanitizer mode loads the
production sources rebuilt with ASan/UBSan and repeats the same assertions.
No actual reboot, sync, accounting write, or runlevel transition is tested.

Build a targeted shell with `./build.sh --include halt,reboot,poweroff --name
sol-halt`, then compile the fixture with `bash tests/sol-halt-build.sh` and
`BASHOS_TASK_DIR` set to an artifact directory. During the completion campaign,
**every build must be wrapped in its build gate**. Run correctness with:

```sh
python3 tests/sol-halt-check.py --binary out/bash-sol-halt \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so"
python3 tests/sol-halt-check.py --binary out/bash-sol-halt \
  --shim "$BASHOS_TASK_DIR/artifacts/boundary.so" \
  --sanitize-dir "$BASHOS_TASK_DIR/artifacts"
```

`bench/sol-halt.py` times three fixed batches: dry-run parsing, forced requests
returning success, and forced requests returning EPERM. Each repeated call's
status is asserted; exact output and boundary counts are checked against
independent expectations. One warm-up precedes seven samples, with a fixed CPU
selected by the campaign bench gate. Reports record distributions, source and
binary hashes, fixture options/reset rules, compiler/library versions, and
host/affinity data. These are parser/syscall-shim timings including shell
startup, loop and validation overhead. No external ratio or shutdown latency
claim is appropriate. Build the fixture separately before timing:

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- python3 bench/sol-halt.py \
  --binary out/bash-sol-halt --shim "$BASHOS_TASK_DIR/artifacts/boundary.so" \
  --runs 7 --passes 10000 --output "$BASHOS_TASK_DIR/benchmark.json"
```

The targeted build and boundary fixtures passed validation in an isolated
checkout. All 108 assertions passed both natively and with ASan/UBSan.
Each of the three benchmark workloads passed its warm-up and seven measured
batches of 10,000 calls. These checks exercise the unchanged production wrapper
behind the closed boundary; they do not qualify real shutdown, storage flushes,
accounting or runlevel changes. Earlier unsuccessful build attempts remain
separate evidence, rather than being treated as runtime passes.

Integration must rerun all three siblings after any subsequent change to the
shared header, reboot or poweroff. Live machine shutdown qualification remains
outside this software scope.
