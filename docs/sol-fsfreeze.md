# fsfreeze software-path qualification

The native build and closed fixture are validated. The 57-case contract suite
passes normally and under ASan/UBSan; the archived pre-hardening source fails
35 cases under the same fixture. The fixture uses `fixture_trace` to avoid a
name collision with Bash's `trace` declaration. The original uncompiled delivery
and its failed evidence remain historical; they are not counted as passes.
No host filesystem was frozen. Actual kernel freeze/thaw behavior remains
unqualified and requires an isolated disposable filesystem.

`fsfreeze` requires exactly one action flag (`-f`/`--freeze` or
`-u`/`--unfreeze`) and one nonempty directory operand. Repeated action flags,
conflicting actions, missing arguments, unknown options, and extra operands
return usage status 2 before any syscall. Options precede the operand; `--`
allows a directory name beginning with `-`. `--help` returns without accessing
a filesystem and reports stdout write failures.

The implementation checks the operand with `stat`, then opens it with
`O_RDONLY | O_DIRECTORY | O_CLOEXEC`. The open therefore checks the actual
object's directory type even if the pathname changes after `stat`. It sends
`FIFREEZE` or `FITHAW` with argument zero and closes the descriptor on both
success and failure. The ioctl errno is saved before close. Runtime failures
return status 1; successful requests return 0 without output. Each invocation
has its own action and descriptor state.

The directory identifies the filesystem for the kernel ioctl. The command
does not parse mount tables or insist that the directory is a mount root;
permission, filesystem support, and current freeze state are decided by the
kernel. A symlink to a directory is followed. The command does not retry an
interrupted ioctl or automatically thaw a successful freeze. A close failure
is not separately reported. These are existing semantics, not qualifications
of a filesystem or a promise of privilege availability.

## Safe fixture coverage

[The fixture](../tests/sol-fsfreeze-fixture.c) includes the production source
and replaces only its `stat`, `open`, `ioctl`, and `close` calls at compile
time. Its ioctl replacement never calls the kernel. Synthetic directory names
are used, and its only real opened object is `/dev/null`. No host mount is
frozen or thawed. The production binary has no fixture environment hook.

[The contract tests](../tests/sol-fsfreeze-check.py) use independent expected
call sequences and Linux request constants. They check parser rejection
before syscalls, short and long action names, option delimiters, paths with
spaces, regular/block object rejection, stat/open errors, permission failures,
unsupported ioctl errors, invalid state, interrupted calls, success for both
requests, and saved errno when close overwrites it. Repeated success and error
pairs run in the same empty-PATH shell with a descriptor limit of 64, checking
both actual descriptor counts and fixture counters. Help write failure and
recovery are covered. Safe native checks retain builtin/help assertions and
add parser and private regular-file rejection checks.

Compile separately, using the campaign build gate for **both** commands:

```sh
./build.sh --include fsfreeze --name sol-fsfreeze
bash tests/sol-fsfreeze-build.sh /absolute/evidence/modules
```

The selection requires no companion loadables, external libraries, or shared
helper changes; the build system includes its default `_jsmn` helper. The
fixture build uses headers from that worktree's completed native build and
produces optimized and ASan/UBSan shared modules. It does not run tests or
measurements. Run correctness checks without compiling:

```sh
python3 tests/sol-fsfreeze-check.py --binary out/bash-sol-fsfreeze \
  --module /absolute/evidence/modules/fsfreeze.so
python3 tests/sol-fsfreeze-check.py --binary out/bash-sol-fsfreeze \
  --module /absolute/evidence/modules/fsfreeze-sanitize.so \
  --asan-library /absolute/path/to/libasan.so
```

ASan leak detection is disabled for the uninstrumented Bash runtime; descriptor
leaks are checked explicitly. The command implementation and syscall fixture
are compiled with ASan/UBSan for the second run. This does not instrument all
of Bash.

## Timing scope

[The benchmark](../bench/sol-fsfreeze.py) measures a fixed batch of 10,000
freeze/thaw pairs through the intercepted production code. It validates every
builtin status, strict freeze/thaw request alternation, exact final syscall
counts, zero bad requests, zero outstanding
fixture descriptors, unchanged shell descriptor counts, stdout, and stderr on
every batch. One warmup precedes seven samples on a recorded CPU affinity.
Each batch starts a fresh shell and resets the fixture. All calls within a
batch share the same shell. Sources, binary, module and fixture hashes,
compiler/Bash/Python/kernel/libc versions, script, expected output, work counts,
and each sample are recorded in the raw JSON. The adapter refuses to overwrite
an existing report or accept fewer than seven samples.

Run through the campaign **bench gate**, after the separate gated builds:

```sh
python3 bench/sol-fsfreeze.py --binary out/bash-sol-fsfreeze \
  --module /absolute/evidence/modules/fsfreeze.so --runs 7 --pairs 10000 \
  --output /absolute/evidence/fsfreeze-shim.json
```

This is **syscall-shim workload timing**: it includes shell startup, module
loading, parsing, synthetic stat/ioctl dispatch, real `/dev/null` open/close,
shell loops and checks. It has no external comparison ratio. It does not
measure filesystem writeback, real freeze/thaw latency, or real-device
throughput. No previous validated fsfreeze timing or performance bottleneck
was supplied; this work makes no speedup claim. Actual filesystem qualification
requires a separately authorized disposable filesystem and remains unperformed.
