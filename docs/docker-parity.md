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
