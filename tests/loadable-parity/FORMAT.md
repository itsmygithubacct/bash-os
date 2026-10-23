# Loadable parity fixtures

Run the reviewed regression suites together with:

```sh
systemd-run --user --scope -p CPUQuota=75% -p MemoryMax=1G -p TasksMax=64 \
  python3 tests/loadable-parity/run.py --binary out/bash-static \
  --output /tmp/bash-os-parity-results
```

The output directory must not already exist. Additional positional arguments
select JSON files or directories instead of the default `regressions/` directory.
`summary.json` records binary and fixture hashes, per-suite results, and separate
parity, contract and deferred counts. A missing reference is a skip, an invalid
reference expectation is an error, and a deferred operation never counts as a
pass. These fixtures cover the behavior listed in each file, not complete GNU
command conformance. `test_runner.py` checks the runner's isolation and result
classification using the binary named by `BASHOS_TEST_BINARY`.

`runner.py SUITE.json --binary /absolute/bash-os --output NEW-DIRECTORY`
runs each fixture in a fresh bubblewrap namespace. Bubblewrap is mandatory;
there is no fallback to executing test commands on the host. Python, Bash, and
GNU reference tools are used from the host's read-only `/usr` tree. Tests have
private process, network, IPC, mount and user namespaces; no capabilities; no
host home, devices or service sockets; private temporary storage; and CPU,
memory, file size and wall-clock limits. A mandatory libseccomp filter also denies
global kernel changes, swap/reboot/module operations, shared kernel keyrings and
cross-process tracing. Run the containing worker in a cgroup
with a process limit as well. Source and test definitions are data, not trusted
host programs. Never source generated fixtures in an unrestricted host shell.

The JSON object has `version: 1`, `loadable`, `reference` (description of the
independent oracle), `coverage` (list), `exclusions` (list), and `cases` (list).
Set `optional: true` only for a catalog entry from the optional list.

Each case has a unique portable `id`, a `purpose`, and a `kind`:

* `parity`: execute the same `script` with system Bash/GNU tools and with the
  bash-os binary and an empty executable search path. Name required external
  reference programs in `requires`. The expected exit status must first be
  validated against the reference. Compare stdout bytes and filesystem contents,
  permissions, hardlink relationships and symlink targets. `compare_tree: false`
  requires a specific explanation in `purpose` (for inherently varying artifacts).
* `contract`: no matching external CLI exists. Supply an independent, documented
  expected `stdout` string or `stdout_base64`. Do not describe this as GNU parity.
* `deferred`: supply `reason` describing the missing disposable VM, hardware,
  privileged mock, terminal driver, or reference dependency. No script executes,
  and this does not count as a pass.

Runnable cases need `script`, `expected_status` (integer), and `stderr`:
`empty`, `nonempty` (diagnostic wording may vary), or `exact`. Contract cases
with exact stderr also need `stderr_text`. `timeout` defaults to five seconds
and cannot exceed fifteen. The shell enables `errexit` and `pipefail`; explicitly
capture a command's failure before checking its effects. Do not mask failures
with `|| true`, normalize away substantive differences, or derive the expected
answer from the candidate implementation. Known compatibility failures remain
failing tests, with details in the separate review report.

Use relative fixture paths, deterministic small inputs, C locale and UTC.
No absolute device/system paths, real network peers, installed user credentials,
system-service changes, package installations, stress loads or host process
signals. Operations involving reboot, mounts, raw devices, kernel changes,
users/authentication, firewall/routing or system-wide process control must be
deferred or use independently reviewed syscall mocks in a separate future test.
Availability/help metadata can be checked through Bash's `type` and `help`
builtins without invoking those loadables. Do not count metadata as operation
coverage. Interactive applications need deferred PTY cases if no bounded fixture
can exercise useful behavior without a real terminal.

Prefer 6–12 meaningful cases per loadable: common behavior, multiple inputs,
options, ordinary boundary values, expected errors and resulting file effects.
Use fewer when the command has a narrow contract; record why. Destructive inputs,
crash reproduction, sandbox probing or exploit tests are outside this suite.

Missing references and optional loadables are `SKIP`; unavailable environments
are `DEFERRED`; invalid GNU expectations or harness failures are `ERROR`;
candidate differences are `FAIL`. Only executed, verified comparisons are `PASS`.
