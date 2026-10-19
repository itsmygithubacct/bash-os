# bsdgames filters and deterministic input contracts

This report covers the native `bsdgames rot13` and explicit-shift `caesar`
filters, with representative contracts for `number`, `morse`, `primes`, the
bounded Adventure adapter and seeded Wumpus. It does not establish upstream
BSD-games parity for every adapter or replace their documented scope limits.
The available ROT13 reference is GNU `tr A-Za-z N-ZA-Mn-za-m` under `LC_ALL=C`.
It maps ASCII letters and preserves all other bytes, including NUL and bytes
128–255. Arguments are joined with spaces and receive a trailing newline;
stdin is a byte filter and preserves the input's final-newline state.

`tests/sol-bsdgames-contracts.py BINARY` exercises pipes and regular files,
empty input, every byte, mixed binary records, multi-MiB lines, dense newlines,
and 64 KiB boundaries. Repeated calls in one shell distinguish different
inputs by their bytes. A `number` call followed by ROT13 tests stdio read-ahead
on the same stream. Early quit followed by different files, the same reopened
inode, a pipe and here-strings checks for stale buffered commands. Empty `PATH`, output ordering, read and write errors,
recovery after errors, closed descriptors, ignored-SIGPIPE handling, descriptor
counts, and line delivery before EOF on a pipe and a private PTY are covered.
Game checks include known prime values, Morse output, Adventure inventory and
movement, and seeded Wumpus invalid-command and quit handling. Their state root
is private and the tested games must leave it unused.

Build only the command:

```sh
./build.sh --include bsdgames --name sol-bsdgames --no-strip
python3 tests/large-smoke.py out/bash-sol-bsdgames bsdgames
python3 tests/sol-bsdgames-contracts.py out/bash-sol-bsdgames
```

`config/helpers.json` declares no required companion for `bsdgames`; selection
uses the shell base and the default `_jsmn` header helper. No common helper or
catalog file is modified by this task. Campaign builds and measurements must
be wrapped by the campaign's `gated.py build --` and `gated.py bench --`
respectively. The commands above are the wrapped payloads, not instructions to
bypass that gate.

For sanitizer checks, set `BASHOS_TASK_DIR` to a private artifact directory,
build with `bash tests/sol-bsdgames-build.sh` through the build gate, then run
the focused Python test with `BSDGAMES_LOAD_ENV=$BASHOS_TASK_DIR/load-sanitize.sh` and
`BSDGAMES_ASAN_LIB` set to the path in `asan-library.txt`. The test injects
ASan/UBSan only into child processes, disables leak checking of the host shell,
and aborts on sanitizer errors.
The build script also creates the transform-only measurement executable;
compilation and measurement are separate gated operations.

## Measurement method

The historical case uses 1,680,000 bytes of `00000000 word\n`-shaped records,
120,000 records, three passes and seven samples. The shared `bench/loadables.py`
case is invoked unchanged to reproduce its calling pattern and validation.
The historical 100.655/8.014 ms result is context, not a paired baseline for
this host/build.

`bench/sol-bsdgames.py --before BEFORE --before-source BEFORE_SOURCE --after AFTER --output REPORT` measures
that exact fixture, binary inputs from zero through 8 MiB, an 8 MiB line and
1 MiB of dense newlines. Each implementation runs in a persistent shell loop,
with stdin reopened for each pass. There is one warm-up and at least seven
samples, with implementation order rotated and reversed. Every call's status
is checked and every timed batch's complete output is compared with an
independent ASCII translation oracle and GNU `tr`. Output is a private regular
file, truncated before each batch; validation occurs after timing. These file
sink results must be distinguished from the shared benchmark's `/dev/null`
sink. Every sample records the output digest and validated pass count.

The report gives outer process/driver wall time and Bash's internal batch time
separately, along with an empty-loop control. Bash's millisecond time reporting
limits resolution for tiny inputs. No subtraction is presented as a pure
transform estimate. `tests/sol-bsdgames-transform.c` includes the production
source and calls the actual translation function. It times only translation,
excluding allocation, input, map setup, output, launch and validation. Every
8 MiB pass is checked against an independently constructed alphabet-half
oracle, with one warm-up and seven samples of sixteen passes each. That is an
API microbenchmark, with no external-tool ratio.

## Correctness changes

The argument-text path now checks each output write and the final flush.
Previously `bsdgames rot13 hello > /dev/full` returned success. Both the
argument and stdin forms now return failure for this condition and can be
followed by a healthy call in the same shell.

The entrypoint also distinguishes input streams by their descriptor's device,
inode and type, clearing stale stdio read-ahead when the input changes. After
a game finishes with regular-file stdin, POSIX input `fflush` synchronizes the
file descriptor to the logical read position before Bash restores redirections.
This prevents an early `quit` followed by a new redirection from executing old
buffered commands, including when the same inode is reopened. Sequential games
on one pipe retain their unread bytes; sequential readers of one open regular
file see the correct remaining bytes. No descriptors are retained between calls.
The stream check uses Bash's existing portable `fpurge` API; no common helper
implementation changes are needed.

## Validation and remaining performance work

The final targeted binary passed 136 focused contract checks and the 12
unchanged `large-smoke.py` bsdgames checks. Both sets also passed with the
production implementation loaded under ASan and UBSan. The initial code failed
the new `/dev/full` argument-mode assertion and early-quit/reopened-input
assertions; the final code passes them.

**Performance completion is blocked.** The mandatory campaign gate did not
admit any of the three queued measurement jobs. A captured resource snapshot
showed a one-minute load average of 25.45 against an admission threshold of
9.6 for the twelve allowed CPUs; memory and I/O pressure were below their
limits. After a sustained wait, only this task's three idle gate processes
were stopped. None had spawned a measurement subprocess. Their failed/canceled
commands and logs are included in the task result receipt. No current timing,
syscall profile, hardware-counter result or transform-only timing is claimed.

Static inspection of historical source `63cb23d` shows a `getchar`/`putchar`
loop with alphabet tests and modulo arithmetic. The assigned baseline already
has a lookup table and 64 KiB regular-file input/output blocks. This difference
is a reason to remeasure, and does not establish that the former 12.56× slowdown
has been resolved. The extracted `bsdg_caesar_transform` retains the baseline
lookup algorithm so the separately compiled harness can measure actual
production code. No speculative algorithm or output-buffering change was made.

The remaining work is to run the unchanged historical benchmark against the
baseline and final binaries, collect syscall/counter evidence where available,
and execute the task-owned size sweep and production transform microbenchmark
through the bench gate. The size-sweep driver has been syntax-checked; its
measurement path has not executed. Additional optimization needs that evidence.
Keep all new raw reports separate from historical datasets.
