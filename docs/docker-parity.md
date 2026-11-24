# Docker parity

`scripts/docker-parity.py` runs the same inputs in two existing Docker images. It supports scripts with separate stdin data, the GNU fixture suite, interactive event replay, and live terminal input mirrored to both shells. It records image IDs, Bash versions, executable hashes, inputs, output, exit status, and filesystem changes for reproduction.

The default images are `bash-os:parity-debian` and `bash-os:parity-bash-os`. Both must be installed locally and have a Bash-compatible shell entrypoint. The reference must report Bash 5.3.20. Select alternatives with `--reference IMAGE` and `--candidate IMAGE`. The runner resolves tags to immutable image IDs before starting tests; it does not build, pull, or modify images. A Python 3.11 or newer host and Docker CLI are required.

## Workspace

Choose a writable directory on the disk intended for active test work:

```sh
export PARITY_WORKSPACE=/path/on/nvme/bash-os-parity
```

Every invocation creates a new directory under `$PARITY_WORKSPACE/results`. Use `--output NEW_DIRECTORY` to choose an exact result location. Existing result directories are never reused. To keep active work off archive-only storage, set `BASH_OS_ARCHIVE_PATHS` to a colon-separated list of directories; a workspace, output, or fixture under one of them, including through symlinks, is rejected.

Each container gets its own writable fixture mounted at `/work`, with the same user/group IDs, environment overrides, hostname, CPU/memory limits, and working directory. The root filesystem is read-only; `/tmp` is a separate memory filesystem and networking is disabled. Writable files under `/work` are retained for comparison. `/tmp`, network behavior, ownership changes requiring privileges, and other system side effects are outside this runner's filesystem comparison.

The host workspace holds fixtures, input captures, and logs. Docker still uses its configured storage for image layers and container metadata; selecting this workspace does not relocate the daemon. Container logging is disabled because the runner captures output directly. Containers are removed on completion, failure, timeout, interruption, or terminal hangup; evidence remains in the workspace.

## Batch scripts

Start with the hello-world case, which prints `Hello, world!` followed by a newline:

```sh
python3 scripts/docker-parity.py run \
  --workspace "$PARITY_WORKSPACE" \
  --script tests/docker-parity/hello-world.sh
```

For a script with arguments and separate input data:

```sh
python3 scripts/docker-parity.py run \
  --workspace "$PARITY_WORKSPACE" \
  --script my-test.sh --stdin input.bin --arg='two words'
```

The same script is mounted read-only at `/parity/input.sh` in each container. The script receives the same arguments and binary stdin, with separate pipes for each process. This preserves the distinction between shell program text and data consumed by `read`, pipelines, or child programs. State persists throughout the script. Repeated `--arg=VALUE` options supply more arguments.

Use `--fixture DIRECTORY` to start both sides from a saved fixture. Regular files, directories, symbolic links, and hard links are supported. A pristine copy is retained with the results, so subsequent fixture changes do not invalidate reproduction. The original fixture is untouched. Keep output directories outside the fixture.

The runner compares raw stdout and stderr bytes, exit status, and the `/work` tree's file bytes, modes, symlink targets, hard-link topology, and special-file types. Entries a test makes unreadable, such as after `chmod 0 dir`, are read with temporary owner permission and their modes are restored, so their contents are still compared. Times and inode numbers are not compared. The reference must also exit with the expected status, default zero; use `--expect-status N` for a test expecting an error. Two identical failing executions do not pass a test that expects success.

`--timeout SECONDS` bounds each execution, including Docker attach. The default is 30 seconds. `--memory` defaults to `512m`; `--cpus` defaults to `2`. A timeout, Docker failure, or out-of-memory termination cannot produce a pass.

## Existing GNU fixture suite

```sh
python3 scripts/docker-parity.py suite \
  --workspace "$PARITY_WORKSPACE" --timeout 120
```

This runs `tests/bash-gnu-parity.sh` in `gnu` mode in the reference and `builtins` mode in bash-os, then runs `tests/compare-parity.py` on the host. The reference image needs the external utilities exercised by that suite; a bare Bash image is insufficient. Builtins mode clears `PATH` as the existing collector specifies.

The suite retains its established diagnostic policy: cases marked as diagnostic require stderr on both sides but allow different wording. The standalone `run` mode instead compares stderr exactly. Incomplete collectors or failed comparisons produce a failure; see `comparison.log` and `comparison.json` in the result directory for details.

## Interactive replay

```sh
python3 scripts/docker-parity.py replay \
  --workspace "$PARITY_WORKSPACE" \
  --events tests/docker-parity/interactive.json
```

Each shell has an independent PTY. Event files contain a JSON array of these operations:

| Event | Meaning |
| --- | --- |
| `{"send":"printf 'hello\\n'\n"}` | Send the UTF-8 bytes to both terminals. |
| `{"send_b64":"Aw=="}` | Send arbitrary bytes; this example is Ctrl-C. |
| `{"expect":"parity> ","timeout":5}` | Wait until both streams contain the bytes after their previous expectation; advance both cursors. |
| `{"expect_b64":"..."}` | Match arbitrary bytes, with the same cursor behavior. |
| `{"resize":[30,100]}` | Set both terminals to 30 rows and 100 columns. |
| `{"signal":"SIGINT"}` | Send a signal to each container's main process. Also supports SIGTERM, SIGHUP, and SIGWINCH. |
| `{"eof":true}` | Send terminal EOT (Ctrl-D). This is terminal input, not closing the Docker socket. |
| `{"sleep":0.1}` | Wait while continuing to drain both outputs. |

Finish an event sequence by exiting both shells, normally with `exit 0\n`, or with terminal EOF when appropriate. The runner waits for both exits with a bounded timeout. Terminal resizing uses Docker's Unix-socket API and currently requires a local Unix-socket Docker context.

Use output checkpoints between dependent actions. Readline emits control sequences around prompts; match the command's result and the prompt as separate expectations instead of assuming they are adjacent. The supplied interactive fixture covers shell state, resize, `read`, editing, and interruption.

PTY stdout/stderr form a single terminal stream. The runner compares it byte for byte and retains both raw transcripts. Equivalent screens can still have different redraw sequences, and differing timing can change which command consumes later keystrokes. These are reported as raw stream differences; there is no implicit screen normalization or guarantee that equal bytes imply identical scheduling.

## Live input mirroring

```sh
python3 scripts/docker-parity.py live --workspace "$PARITY_WORKSPACE"
```

Type once and both container shells receive the same bytes. The reference terminal is displayed; both outputs are recorded. Window resizes are delivered to both; a terminal that reports no size leaves both shells at Docker's default. Shell state persists within each session. Enter `exit` to finish and compare; **Ctrl-]** aborts the session, restores the host terminal, and removes the containers without reporting a parity pass.

Live mode saves binary input events and the delays between them to `events.json`. Replay those events with `replay`, or use the saved reproduction command below. Live input follows the reference's visible progress; a slower candidate may consume a later keystroke differently. For repeatable regression tests, replace timing-only pauses with explicit output checkpoints.

## Evidence and reproduction

Each result directory contains:

- `run.json`: requested images, immutable IDs, image configurations, versions, executable hashes, runner hash, environment, and resource limits.
- `report.json`: final status, pass/fail, differences, and container outcomes. A missing or incomplete report is not a pass.
- `input.sh`, `stdin`, or `events.json`, plus the pristine `fixture/` and a saved copy of the runner and any suite dependencies.
- `reference/` and `candidate/`: output streams, container state, filesystem snapshots, and resulting writable trees. Interactive output is in `terminal`; Docker client diagnostics are separate.
- `replay-command.json`: the exact argument array to run the saved inputs and driver against the recorded image IDs, creating a new result directory.

To execute a saved reproduction command:

```sh
python3 - /path/to/result/replay-command.json <<'PY'
import json, subprocess, sys
raise SystemExit(subprocess.run(json.load(open(sys.argv[1]))).returncode)
PY
```

The images identified in that command must remain available locally. Exit status zero means all comparisons and reference expectations passed. Status one means a completed comparison failed, including batch timeouts. Status two means a runner error, an interactive checkpoint timeout, interruption, or incomplete suite. Consult `report.json` for the specific cause.

Validate the harness against the installed images with:

```sh
python3 tests/docker-parity-check.py --workspace "$PARITY_WORKSPACE"
```

This checks matching execution, saved-input reproduction, deliberate stdout/stderr/status/filesystem differences, unreadable entries, reference failure, binary input, timeout cleanup, interactive behavior, live capture/replay, and cleanup after a terminal hangup. These checks validate the harness; they are separate from a claim of complete Bash or command compatibility.

## Parity suite

`scripts/docker-parity-suite.py` runs every case in `tests/docker-parity/suite` through this runner, one `run` (or `replay`) invocation per case, and classifies the results against `tests/docker-parity/suite/known-differences.json`:

```sh
python3 scripts/docker-parity-suite.py --workspace "$PARITY_WORKSPACE"            # all cases
python3 scripts/docker-parity-suite.py --workspace "$PARITY_WORKSPACE" --area text --area sed
python3 scripts/docker-parity-suite.py --workspace "$PARITY_WORKSPACE" 'errors/*' --case 'files/ls-*'
python3 scripts/docker-parity-suite.py --list                                    # show the selection
```

`--workspace` defaults to `$PARITY_WORKSPACE`. `--jobs N` (default 6) runs that many cases at once; each case starts two containers, so keep it well below the host's core count when other work shares the machine. The image tags are resolved once and every case runs against the same immutable image IDs, which the driver prints at the start and end and records in the summary. `--timeout`, `--memory` and `--cpus` are passed to the runner. `--compare EARLIER/summary.json` lists every case whose result changed since an earlier run, which is the check for flaky cases.

Each run writes a new directory, `WORKSPACE/suite-results/TIMESTAMP` (or `--output`): `cases/AREA/NAME/` holds that case's complete runner evidence (`report.json`, both output streams, both trees, `replay-command.json`), `cases/AREA/NAME.log` the runner's own output, and `summary.json` and `summary.md` the per-area table followed by every failure with a short diff. A result is one of:

| Result | Meaning |
| --- | --- |
| pass | The runner found no difference. |
| fail | The case differs, or the runner reported an error, and no known difference covers it. |
| xfail | A known difference that still differs, only in the aspects its entry allows. |
| xpass | A known difference that now matches. Remove the entry. |

The driver exits 0 only when every selected case is a pass or an xfail. A full run (no `--area` or pattern) also fails on a known-differences entry that names no case.

### Adding a case

A case is a Bash script, `tests/docker-parity/suite/AREA/NAME.sh`, with id `AREA/NAME`. It runs from `/work` in both images exactly as `run` mode runs a script. Keep it small and deterministic:

- Set `export LC_ALL=C TZ=UTC0` (or `C.UTF-8` for a multibyte case) and `umask 022` at the top.
- Give files fixed times with `touch -d @N`, and format dates from fixed epochs (`date -u -d @N`).
- Do not depend on PIDs, the clock, host or user names, or directory order: sort listings unless the order is the subject of the case, and show modes and sizes rather than owners (`ls -lgo`, `stat -c`).
- Report the status of an expected error inline (`cmd; echo "rc=$?"`) so the script itself exits 0. Use a `.status` sidecar only when the script's own exit status is the point.
- Keep files that embed the time or that are implementation-specific but not under test (archives that are only listed or extracted, incremental snapshots) under `/tmp`, which is not compared.
- When a command exists in the candidate only as a `coreutils` verb, add `command -v NAME >/dev/null || NAME() { coreutils NAME "$@"; }` so the case tests the behaviour, not the name.
- When a case finds a bug, move the failing commands into their own case so that the rest of the original case keeps guarding.

Optional sidecars next to the script: `NAME.stdin` (bytes for the script's stdin), `NAME.args` (one argument per line), `NAME.status` (the expected reference exit status), `NAME.timeout` (seconds) and a `NAME.fixture/` directory (the starting `/work` tree). An interactive case is `AREA/NAME.replay.json`, an event file in the format described under [Interactive replay](#interactive-replay); compare only behaviour whose terminal bytes are stable, since full-screen redraws differ between implementations.

Run the new case on its own (`--case AREA/NAME`) and then twice in a full run with `--compare` before committing it.

### Known differences

`known-differences.json` maps a case id to an entry with a `category`, a `reason` and, optionally, `differences`, the aspects that may differ (`stdout`, `stderr`, `terminal`, `exit status`, `filesystem`, `candidate` for a candidate timeout or crash). An entry without `differences` allows any candidate-side difference; a difference in an undeclared aspect, any reference failure and any runner error is still a fail. Keys starting with `_` are comments.

The categories are:

| Category | Use for |
| --- | --- |
| `version-string` | `--version` or help/usage text that names the bash-os implementation and does not claim to be GNU. |
| `known-partial` | Behaviour documented as a known partial implementation. |
| `missing-tool` | A command that one image does not provide. |
| `by-design` | A documented, deliberate bash-os behaviour (for example the awk `system()` gate). |
| `environment` | An image difference outside the command itself, such as missing data files or locales. |

Only accepted, real differences belong in the file. A bug is reported and its case is left failing until it is fixed; it is never listed as a known difference. When a known difference disappears the case is reported as an xpass, and the entry should be removed.

Validate the driver itself with:

```sh
python3 tests/docker-parity-suite-check.py --workspace "$PARITY_WORKSPACE"
```

It plants a matching case, a failing case, known differences that still differ, that now match, that differ in an undeclared stream or that break the reference, sidecar files, a replay case and a stale entry, and checks the driver's classification, exit status, summaries and container cleanup.
