# Disposable parity VM

`tests/parity-vm/vm.py` prepares a reference image and runs each evaluation in a
fresh disposable overlay. Candidates, terminal programs, and network fixtures
execute in the guest. The host handles QEMU, transport, pinned downloads, and
evidence files. There are no host filesystem mounts or forwarded agent sockets.

The controller requires Linux, KVM access, QEMU, qemu-img, xorriso, OpenSSH,
Python 3.11 or newer, and a user systemd manager. The guest uses two virtual CPUs
and 2 GiB of RAM. A host scope caps CPU at 150%, memory at 3 GiB, swap at zero,
and tasks at 128. One VM may use a cache at a time.

Keep the cache and results outside the checkout. They contain synthetic SSH
credentials, guest disks, and raw diagnostic evidence.

```sh
PARITY_CACHE="$HOME/.cache/bash-os-parity"
python3 tests/parity-vm/vm.py --cache "$PARITY_CACHE" prepare
python3 tests/parity-vm/vm.py --cache "$PARITY_CACHE" check \
  --output "$HOME/parity-results/lifecycle-1"
python3 tests/parity-vm/vm.py --cache "$PARITY_CACHE" run \
  --binary out/bash-static --output "$HOME/parity-results/static-1" \
  --groups shell,terminal,network,legacy,selfcheck,inventory
```

Output directories must be new. Repeat with `out/bash` and a different output
directory for the dynamic binary. Run the independent reference-data CLI
described by `python3 tests/parity-vm/references.py --help`, then pass its verified
data directory with `--references DIR`. Run `--groups reference` separately:
its exhaustive sweeps have their own 1,100-second budget inside the guest's
1,800-second evaluation limit.

```sh
PARITY_DATA="$HOME/.cache/bash-os-unicode17"
python3 tests/parity-vm/references.py fetch --dest "$PARITY_DATA"
python3 tests/parity-vm/references.py verify --dest "$PARITY_DATA"
python3 tests/parity-vm/vm.py --cache "$PARITY_CACHE" run \
  --binary out/bash-static --output "$HOME/parity-results/reference-static-1" \
  --references "$PARITY_DATA" --groups reference
```

The reference group streams Unicode 17 grapheme, normalization, case mapping,
case folding, comparison and malformed-UTF-8 assertions, plus pinned RFC
cryptographic and encoding vectors. Expected values come from the locked
corpora and independent derivations. It probes generated RFC argument lists
with trusted Bash before invoking the candidate. `references.py generate`
can export the plan; `--sample 10` writes a small sample while still counting
every planned assertion.

Each corpus record distinguishes planned, executed, passing, failing and
unexecuted assertions. Batch logs include argument/output hashes and assertion
ranges. Compressed raw batch output is capped at 48 MiB; the batch log records
whether each output was archived. The separate failures log has a recorded
cap as well. NUL-containing shell arguments, unavailable casing interfaces and
unsupported RFC vectors have explicit exclusions. The upstream Bash/Coreutils
corpus lock is a proposal with verified downloads; those upstream suites have
not been integrated or executed by this harness.

Preparation verifies the pinned Debian image and GNU Bash source/patch hashes,
installs reference packages, builds Bash 5.3.15, records installed versions, and
seals a flattened image. Reusing the cache checks the image and specification
hashes. Changed specifications require a new cache. A failed preparation retains
its scratch disk and logs for diagnosis. Debian Trixie's GRUB configuration needs
an emulated VGA adapter even with `-display none`; the controller supplies it.
Package installation uses live Debian repositories; a fresh preparation may
select different package versions. Its manifest records that difference.
An uncatchable controller `SIGKILL` stops its VM through the parent-death signal
but can leave an overlay and no final provenance file; that interrupted run is
not qualification evidence.

Runtime networking is restricted. Before uploading the candidate, the controller
checks VM identity, absence of shared mounts, and refusal of outbound access to
a host canary and a previously reachable package mirror. Fixture execution uses
a separate network namespace with only loopback, plus fresh PID and mount
namespaces. Test subprocesses run as synthetic uid/gid 2000 with time, output,
file-size, descriptor, and address-space bounds. The historical suite retains
its additional bubblewrap and seccomp isolation inside the VM, with its runner
also using uid/gid 2000. Fresh tmpfs mounts reset `/tmp`, `/var/tmp`, `/dev/shm`
and `/home/parity` between the new fixtures' reference and candidate sides.
Plain-driver cases may explicitly set `file_size_limit` in bytes, from 8 MiB
through 128 MiB, when a filesystem fixture needs a larger image. The default
remains 8 MiB. The allowance applies to trusted setup and behavior on both sides;
uid/gid, CPU, address-space, descriptor and core limits retain their defaults.
Scratch filesystem capacities and the 16 MiB captured-file total remain bounded,
so large-image fixtures must retain compact observations and remove their images
before evidence collection. The guest selfcheck verifies both the default and a
72 MiB allowance, including rejection of a write beyond each limit.
A plain or PTY fixture may set `"privilege": "root"` when its obligation needs
real kernel privilege (block devices, mounts, swap, foreign ownership, clocks).
Each side then runs as uid 0 with full capabilities, in a forked evaluator child
that has fresh mount, network, UTS and IPC namespaces, so its mounts, links and
hostname vanish with it. Kernel objects those namespaces do not cover are
snapshotted before the side and undone afterwards: swap areas, device-mapper
devices, loop devices and a moved realtime clock. Anything still present after
that cleanup makes the side a harness ERROR. The guest runs root fixtures, and
a `root-isolation` selfcheck that proves this containment, only when the
controller is started with `--allow-root-fixtures`; this flag is used on
rented disposable hosts, never on a workstation. Where such a host has no
usable `/dev/kvm`, `--accel tcg` emulates the guest CPU instead, with longer
boot allowances; provenance records the accelerator and the flag.
The historical runner sets its guest audit login ID to 2000 and adds a
supplementary group absent from its synthetic group database. This makes its
`logname` and unmapped-group fixtures independent of the host's login session;
the actual identity is saved with the evidence.

## Groups and evidence

| Group | What it records |
|---|---|
| `shell` | Bash language/builtin behavior against the pinned Bash 5.3.15 build. |
| `terminal` | Controlling PTY steps, raw bytes, decoded screen assertions, terminal modes, process cleanup, and file effects. |
| `network` | Deterministic loopback peers, requests, responses, status, bytes, and file effects. |
| `reference` | Independently derived normative-data assertions, corpus hashes, assertion totals, and explicit exclusions. |
| `legacy` | Every existing loadable suite, including unexecuted deferrals; its shell remains Debian `/bin/bash`. |
| `selfcheck` | Harness bounds, reference-error classification, mismatch classification, and namespace checks. |
| `inventory` | Runtime builtin names, shell options, GNU Coreutils interfaces and versions. This is metadata collection. |

`summary.json` separates counts by group and kind, supplies parity-only totals,
and records the candidate hash,
fixture hashes, reference shell versions, and isolation observations.
`evidence.tar` preserves per-side output, file snapshots, PTY event records and
reference details. The host retains this archive without extracting guest paths.
Fixtures may request `diagnostic_files`, a list of relative paths under the
private guest `HOME`. These logs are retained in each side's raw JSON, including
when setup fails. They are supplemental evidence; required file effects still
need explicit assertions. Diagnostic logs are not part of the compared file
tree. Capture refuses symlinks and special files, limits each file to 1 MiB and
the total to 4 MiB, and records missing files or truncation.
`provenance.json` records lifecycle status, payload and base hashes, teardown,
and actual overlay deletion. A nonzero harness or collection result must be
investigated even when individual cases passed.

Metadata has status `COLLECTED`; harness selfchecks and normative-corpus records
have separate kinds. Corpus records include assertion counts and exclusions;
do not add their millions of assertions to the number of fixture cases.
Legacy results are journaled after each suite so completed results survive a
later infrastructure failure.

The same controller can run on another Linux host reached over SSH. Copy the
flattened `prepared.qcow2`, `prepared.json`, the two test harness directories,
candidate and reference data into a private directory there. Keep the same
repository-relative layout. The controller rehashes the image and candidate;
it creates fresh transport keys on that host. Use local disk for cache/results,
run `check` before test execution, and retrieve the evidence as files. Host
kernel, QEMU version and resource limits are recorded in runtime provenance.

An invalid reference expectation is `ERROR`; a valid reference with a candidate
mismatch is `FAIL`. A `contract` case checks an explicitly described independent
expectation without a GNU reference executable. A `covers` link identifies a
related historical topic. It does not resolve a compound deferral or imply full
option coverage. Exact output/status/file comparisons and semantic PTY checks
are labeled separately; raw evidence is retained in both cases.

Data-only checks can run without a VM:

```sh
python3 tests/parity-vm/schema.py
python3 tests/parity-vm/selfcheck.py
```

These validate fixture structure and rejection paths. They do not execute the
candidate or establish behavioral parity. `guest.py` refuses ordinary host
execution without the matching VM marker, DMI identity and guest isolation.

See [parity scope](parity-scope.md) for the full inventory and remaining work.

## 0.1.3 evidence snapshot batch-220

Migration remains in progress. The selected evidence contains 4,821 unique
candidate case records per build: 4,798 executed cases and 23
SKIP records. The selection contains 1,603 modern and 3,218 historical
case records, selected once per case ID and current definition from
158 qualified source selections per build. Those selections
refer to 156 distinct saved runs for static and
155 for dynamic; multiple selections can refer
to the same saved run. The earlier batch 92 snapshot contained 4,111
records; this snapshot adds 710 distinct candidate cases. Previously
selected FAIL results remain in the counts.

| Group | Static PASS | Static FAIL | Dynamic PASS | Dynamic FAIL | SKIP per build |
|---|---:|---:|---:|---:|---:|
| Shell and command contracts | 902 | 319 | 903 | 318 | 0 |
| Terminal | 213 | 55 | 213 | 55 | 0 |
| Network | 96 | 18 | 94 | 20 | 0 |
| Historical behavior | 3,171 | 24 | 3,171 | 24 | 23 |
| Total | 4,382 | 416 | 4,381 | 417 | 23 |

The selected behavioral results have zero ERROR statuses. Two earlier DNS
transport probes differ between builds; their launch failures do not establish
certificate validation. Build-specific differences and all retained failures
are listed in the validation record.

The authored inventory contains 1,636 modern definitions:
1,603 selected candidate cases, 9 selected support controls,
and 24 without selected evidence. Separate native controls, guest
selfchecks, archived-evidence audit wrappers, and topic metadata add no
candidate cases. The selection includes 1 candidate-shell basics support control, which adds no candidate coverage. A membership-only projection of a fixture does not add an
execution. Three unselected filesystem diagnostics retain excluded FAIL history
and reasons in the [validation record](data/parity-0.1.3-validation.json).

The [deferral review](parity-deferrals.md) records 355 migrated topics
(static 183 PASS and 172 FAIL; dynamic 184 PASS and 171 FAIL) and 245 unresolved topics per build. They
summarize named checks and add no cases. All 600 original
DEFERRED metadata rows and their original definitions remain recorded.

All guest selfchecks recorded in the selected runs pass. Each run retains its
frozen payload and evidence hashes and its recorded overlay disposition.
Runtime inventory remains `COLLECTED`. The six original job-control fixtures
retain their three successful repeats per build; repeats add no cases.

Each build executes 9,331,283 planned normative assertions: 9,331,243 pass
and 40 fail. The failures concern four non-starter composition exclusions in
NFC/NFKC. At corpus-record level this is 33 PASS, one FAIL and four explicit
SKIP records. The plan excludes NUL inputs, unavailable casing interfaces and
unsupported RFC vectors as detailed in those records. Scalar sweeps, corpus
records and ordinary fixture cases have different denominators.

The [validation record](data/parity-0.1.3-validation.json) separates behavioral
cases, support controls and metadata; lists retained behavioral failures; and
preserves source-run filters and artifact hashes. It records the sealed images,
package versions, unchanged candidate hashes and clean teardown. Private
diagnostic and superseded runs remain outside the selected counts. The first
image's original lock content is unavailable, though its hash and 413-package
map remain; the committed lock describes the later image. The
[scope inventory](data/parity-0.1.3-scope.json) keeps missing commands,
unreviewed option forms and all deferrals visible.
