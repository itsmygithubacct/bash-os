# uclampset — setters, command mode and their evidence

This records the predecessor implementation. Current system-file preflight,
write recovery, command output handling and follow-up measurements are
documented in [the follow-up report](sol-uclampset.md).

`loadables/uclampset.c` now implements the whole util-linux command surface:
PID and thread queries, PID setters, system setters and command mode. Earlier
builds printed the clamps and refused every setter.

## Behaviour

| Form | What happens |
|---|---|
| `uclampset [-a] -p PID` | `sched_getattr` for PID (with `-a`, for every thread in `/proc/PID/task`), printed in util-linux's format |
| `uclampset -s` | prints `$BASHOS_PROC_ROOT/sys/kernel/sched_util_clamp_{min,max}` (default `/proc`) |
| `uclampset [-m MIN] [-M MAX] [-R] [-a] [-v] -p PID` | reads every target, then sends one `sched_setattr` per task |
| `uclampset [-m MIN] [-M MAX] [-v] -s` | writes the changed sysctl files only |
| `uclampset [-m MIN] [-M MAX] [-R] [-v] COMMAND [ARG]...` | forks; the child sets its own clamps and runs COMMAND |

**What a setter may change.** A PID request starts from that task's
`sched_getattr` result and sets `SCHED_FLAG_KEEP_POLICY | SCHED_FLAG_KEEP_PARAMS`.
It also sets `UTIL_CLAMP_MIN` and/or `UTIL_CLAMP_MAX`, but only for the values
given on the command line. Policy, nice, RT priority, the deadline fields and
the EEVDF slice reported in `sched_runtime` therefore go back to the kernel
exactly as it reported them, and the kernel keeps them. `-R` replaces
`KEEP_POLICY` with `SCHED_FLAG_RESET_ON_FORK` and resubmits the policy the task
already has. The kernel ignores the reset-on-fork bit while `KEEP_POLICY` is
set, so this is the only way for `-R` to take effect. The system setter
touches only the two `sched_util_clamp_*` files.

**What is checked before the first change:**

- A value must be a decimal integer, either `-1` or in `0..1024`. The parser
  rejects all six ASCII whitespace forms, fractions, hex, `nan`/`inf`,
  trailing text and overflow.
  util-linux sends values above 1024 to the kernel; this implementation
  rejects them before the call.
- An explicit non-reset MIN/MAX pair must satisfy MIN <= MAX before any
  target is read. Each PID request then replaces only the supplied members
  of that task's current pair and validates the resulting pair, matching
  Linux's [`uclamp_validate`](https://github.com/gregkh/linux/blob/v6.12.111/kernel/sched/syscalls.c#L326-L346).
  If either requested member is `-1`, the comparison is skipped before the
  kernel resets it, as in Linux. This checks a single requested minimum
  against the current maximum, and vice versa, for every thread before
  anything is written. An ambiguous current `0/0` with an absent real
  `/proc/sys/kernel/sched_util_clamp_min` is left to the kernel so a build
  without `CONFIG_UCLAMP_TASK` still returns its real `EOPNOTSUPP` error.
  This read-only support probe uses real `/proc`; `BASHOS_PROC_ROOT` only
  redirects system operations. For `--system`, the new pair is checked
  against the current files; `-1` keeps the corresponding current value.
- A PID must be a decimal integer in `0..INT_MAX`.
- Missing option arguments, a missing target, `--pid` together with
  `--system`, an operand after `--pid`/`--system`, `-a` without `--pid`, and
  `-R` with `--system` are all rejected. util-linux silently ignores the last
  four; here they are errors.
- PID setters read every target with `sched_getattr` before any
  `sched_setattr`. A missing task (`ESRCH`) or a denied read stops the command
  before anything is written, including with `-a`.
- The system setter reads and parses both files, then checks `access(W_OK)`
  on each file it will change. If the new floor is above the current
  ceiling, the ceiling is written first. That way the kernel never sees
  min > max between the two writes. If the second write fails, the first
  file is restored.
- An unsupported kernel (`EOPNOTSUPP`) or a permission failure (`EPERM`) in
  `sched_setattr` rejects that task's request and changes nothing for that
  task. The kernel's error text is reported unchanged. Runtime failures or
  concurrent task changes can still leave a multi-thread update partially
  applied; there is no kernel transaction spanning tasks.

**Command mode.** The parent validates against its own attributes, which
the child inherits. It then forks, using the shared `child-wait.h` and
`command-run.h` helpers that `nice` also uses. The child repeats the read so
that a reset-on-fork parent is handled, sets the clamps on itself
(`pid 0`), and runs argv exactly as given: an enabled builtin through
`bos_run_builtin`, anything else through `execvp`. The exit status passes
through unchanged. A signal becomes 128+N, a command that is not found
gives 127 and one that cannot be executed gives 126. If the child cannot
set its clamps it exits 1 without running the command. The parent shell's
clamps, variables and working directory never change.

Failed stdout writes are reported through `sh_chkwrite`
(`uclampset -p PID >/dev/full` exits 1).

## Evidence

`tests/opus-uclampset.py BINARY` has 28 tests. It compiles
`tests/opus-uclampset-shim.c`, so run it through the build gate. The shim is
an `LD_PRELOAD` interposer on `syscall(2)` and on write-mode `open(2)`
calls for the `sched_util_clamp_*` files. In emulation mode it also emulates
the read-only `access(F_OK)` support probe for the real uclamp sysctl. It
records the exact
`sched_setattr` request bytes that the production builtin builds. It can
inject an errno, or emulate the clamp bookkeeping of a `CONFIG_UCLAMP_TASK`
kernel on top of the real `sched_getattr`, so the real kernel still decides
whether a target exists and supplies its policy and nice. The expected
values come from ctypes `sched_getattr`/`sched_setattr`,
`os.sched_getscheduler` and `os.getpriority`, never from the builtin.

The tests cover:

- **Queries.** Queries on an owned `SCHED_BATCH`, nice+5 child must match
  ctypes `sched_getattr`. `-a` must list exactly the threads in
  `/proc/PID/task`. 200 repeated calls in one shell must give identical
  output and leave the descriptor count unchanged. The command must be a
  builtin with help under an empty PATH. A write to `/dev/full` must fail.
- **Validation.** Fourteen malformed values for each of `-m` and `-M`, the
  min > max pairs, malformed PIDs and 21 operand and option errors all
  must exit 1 with empty stdout and no `sched_setattr` in the shim log. A
  missing PID and an injected `EPERM` on read must stop the command before
  any set. All six leading ASCII whitespace forms are rejected for PID and
  clamp arguments before any logged read or write, including system and
  command forms, with private system files unchanged.
- **Real kernel.** The same request goes to the real kernel through ctypes
  (the oracle) and through the builtin, with the shim only logging. On this
  host both get `EOPNOTSUPP`, and the child's clamps are unchanged
  afterwards. On a kernel with uclamp support, the same test does a live
  read/set/read on the owned child and checks that policy and nice are
  unchanged. A separate unsupported-kernel case sends a single minimum
  request despite the kernel's reported `0/0`, even when private system
  fixture files exist, and checks the real `EOPNOTSUPP` refusal.
- **Read/set/read through the emulating shim.** Six steps cover both
  values, a single min, a `-1` max reset, a single valid max, a reset of both,
  and `-R`. Each step
  checks the request flags (`0x78`, `0x38`, `0x58`, `0x31`), `size=56`,
  `flags` argument 0, and that policy, nice, priority, runtime, deadline and
  period match the kernel oracle. A query after each step must show the new
  values. `-v` output is checked as well. Separate cases reject a single
  minimum above the current maximum, a single maximum below the current
  minimum, and a positive minimum for a supported `0/0` task without a set.
  Reset exemptions are checked in both directions. An independent ctypes
  syscall client bypasses builtin preflight and confirms that the shim
  itself rejects invalid single-clamp pairs with `EINVAL` and keeps state.
- **`-a`.** All `get` calls must come before all `set` calls in the log,
  with one set per thread. Threads with different current maxima or minima,
  including a supported `0/0` thread, must reject an incompatible single
  value before any set, leaving every thread's emulated state unchanged.
- **Command mode.** Literal argv (`"a b"`, `*`, `$HOME`, empty) must reach
  the program unchanged, and the exit status 7 must pass through. The set
  must come from the child with `pid=0`. The grandchild must see 64/512
  while the parent still shows the defaults, with its variables untouched.
  A signal gives 143, a missing command 127, a non-executable file 126,
  `false` 1, `cd` in the child leaves `$PWD` alone, and `printf` runs as a
  builtin. When the set fails (`EOPNOTSUPP`/`EPERM`), the command does not
  run. 30 repeated runs must leave the descriptor count unchanged.
- **System setters on a private fixture.** The tests cover queries, missing
  files, five setter steps including `-1` keep-current, verbose output, and
  rejection of min > max (all forms) and garbage contents with the files
  left unchanged. A read-only file must be refused before the other file is
  touched (non-root). Six cases check the write order and the rollback with
  an injected `EIO` when opening the second file. These cases do not inject
  short/failed writes or failed closes.
- **util-linux parity.** Exact stdout, stderr and exit status against
  `/usr/bin/uclampset` 2.41.5 for queries, `-a`, `--pid=`, bad PIDs, missing
  arguments, a missing target, bad values, `ESRCH` and, on kernels without
  uclamp, the refused setter.

`tests/opus-uclampset-sanitize.sh BINARY` builds uclampset as an
ASan/UBSan loadable. It checks that the instrumented object is the one
mapped into the shell, then runs the suite above against it.

## Limits

- The reviewed execution environment runs a Debian 6.12 kernel with
  `CONFIG_UCLAMP_TASK` disabled. A real `sched_setattr` with a clamp
  therefore gets `EOPNOTSUPP` here, and `/proc/sys/kernel/sched_util_clamp_*`
  does not exist. On these kernels, the real-kernel path covered is the
  refusal. The successful PID setter is covered by recording the genuine
  request and emulating the kernel's acceptance. The system setter is
  covered against private files, with injected write failures. The live
  branch of `test_real_kernel_pid_setter` has not run on any host. The same
  applies to a write to the real sysctls, which also needs root.
- `-R` is checked for the request it builds (flags `0x31` with the current
  policy), not for its effect on a later fork.
- If real procfs hides the uclamp sysctl on a supported kernel, an existing
  `0/0` task cannot be distinguished from an unsupported kernel by the
  read-only support probe. That ambiguous case relies on kernel validation
  and does not receive the same preflight guarantee for multi-thread updates.
- All 28 tests, including the five independent-review regressions, passed
  under ASan/UBSan on 2026-10-20. This does not qualify the unavailable
  live-kernel acceptance branch.

## Performance

`bench/opus-uclampset.py BINARY SHIM.so OUTPUT.json` (run through the bench
gate) times N calls in one shell with `$EPOCHREALTIME`. It validates every
pass, warm-up included, against values computed independently, and pins
the CPU.

The figures below precede the effective-limit validation correction and
are retained as earlier measurements, not timings of the final reviewed code.
The separate performance follow-up must remeasure the corrected implementation.

Recorded run: source `ce05eef`, binary SHA-256 `4315b049…96a2`, kernel
6.12.111 (no uclamp), CPU 2 of an i7-9850H. Each figure is 500 calls per
sample, with one warm-up and nine samples. util-linux 2.41.5 is the
reference. Every pass was valid.

| workload | builtin ms/call (median, range) | util-linux ms/call | ratio |
|---|---|---|---|
| query `-p CHILD` | 0.048 (0.043–0.065) | 1.305 (1.269–1.545) | 0.037 |
| refused setter `-m 0 -M 512 -p CHILD` | 0.063 (0.056–0.069) | 1.365 (1.070–1.790) | 0.046 |
| PID setter accepted by the shim (syscall-shim) | 0.181 (0.152–0.239) | — | — |
| system setter on a private fixture (self) | 0.171 (0.152–0.226) | — | — |

The shim figure includes its own log and state-file I/O. The system-setter
figure includes the `eval` that alternates the value. Neither has a matched
reference: util-linux cannot be redirected to a fixture, and this kernel
cannot accept the request. The unchanged `bench/loadables.py --only uclampset`
case (`-p 1`, 130 passes) measured 5.311 ms per batch for the builtin and
113.581 ms for util-linux. The historical figures were 4.706 and 83.286 ms
for 136 passes. A query is one `sched_getattr` and one read of
`/proc/PID/comm`, so no bottleneck remains to optimise. A build was running
on the host during the recorded run, which affects both columns.
