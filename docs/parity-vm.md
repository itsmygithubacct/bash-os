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

The controller option `--image-lock NAME`, given before the operation, selects
another specification file in `tests/parity-vm`; the default is
`image.lock.json`. `image-extended.lock.json` keeps the same Debian image,
guest kernel and reference Bash, and adds reference tools the default image
lacks: ipset, nftables, WireGuard tools, dialog, sharutils, and kitty with Xvfb
and Mesa software rendering. Give each specification its own cache and pass the
same option to `prepare`, `check` and `run`. A cache prepared from a different
specification is refused, and provenance records both the image and
specification hashes. Fixtures that need the added tools should name them in
`requires`, so the default image reports a missing dependency as `ERROR`.
`image-gpu.lock.json` adds the Mesa GBM, EGL and GLES2 runtime and Debian's
generic kernel, whose vgem module a privileged fixture can load. Mesa's
software GBM allocates KMS dumb buffers, which the kernel refuses on render
nodes, so a native context needs vgem's primary node (`gpu start --device`).
The lock's `kernel_flavour` key makes preparation purge every other kernel
image, so the sealed image boots, and its manifest records, only that kernel.
`image-selinux.lock.json` adds the reference SELinux policy, policycoreutils,
selinux-utils and setools. Its `selinux` key boots the guest with
`security=selinux` in the named mode, so SELinux replaces AppArmor as the major
LSM. The provisioning boot still runs AppArmor, so preparation labels the root
filesystem with `setfiles` as its last step, and `check` requires the
configured mode. The image boots permissive: in enforcing mode the reference
policy denies cloud-init's generator, and the guest never accepts the
controller's login. Fixtures run as `system_u:system_r:initrc_t:s0`. A
privileged fixture that needs denials may enforce for its own steps, and must
restore permissive mode and remove any policy module it loaded.
Debian 13 ships no `write` command, so no image provides one.

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

## 0.1.3 release qualification

The deferral review ran on frozen candidates built before the release source.
The 0.1.3 binaries were then built from the release source, and every fixture
definition ran on both of them in disposable guests. Non-root cases ran on the
base, extended and SELinux images; root cases, including the GPU image cases
and the SELinux root case, ran in rented guests. Each build has 6,271 selected
records from 25 runs: all 2,398 modern fixture definitions, 3,821 historical
case rows and 52 harness checks (38 reference corpus records, 13 guest
selfchecks and the runtime inventory).

| Group | Static PASS | Static FAIL | Dynamic PASS | Dynamic FAIL | SKIP per build |
|---|---:|---:|---:|---:|---:|
| Shell and command contracts | 1,437 | 472 | 1,439 | 470 | 0 |
| Terminal | 282 | 90 | 282 | 90 | 0 |
| Network | 96 | 18 | 94 | 20 | 0 |
| Historical behavior | 3,174 | 24 | 3,174 | 24 | 23 |
| Total | 4,989 | 604 | 4,989 | 604 | 23 |

Three definitions per build end in ERROR before a behavioral result: one shell
case whose fixture setup failed, and two terminal cases whose reference run did
not reach the expected screen. None of them is deferral-review evidence. All 13
guest selfchecks pass, and the runtime inventory remains `COLLECTED`. The
historical suites also record 578 deferred rows as migrated and 22 as still
deferred; those metadata rows add no cases.

Each build executes 9,331,283 planned normative assertions: 9,331,243 pass
and 40 fail. The failures concern four non-starter composition exclusions in
NFC/NFKC. At corpus-record level this is 33 PASS, one FAIL and four explicit
SKIP records. The plan excludes NUL inputs, unavailable casing interfaces and
unsupported RFC vectors as detailed in those records. Scalar sweeps, corpus
records and ordinary fixture cases have different denominators.

On the release binaries the 600 topics resolve as static 280 PASS, 256 FAIL
and 64 UNRESOLVED, and dynamic 281 PASS, 255 FAIL and 64 UNRESOLVED. The
unresolved topics are the 22 with [concrete limits](parity-deferrals.md#concrete-limits)
and 42 whose evidence comes from controller pipelines that plain runs cannot
execute. Plain variants of their cases run on the release binaries for 22 of
the 42; their results match the frozen candidates except for three cases fixed
after the freeze (two quoted `sftp` transfers and one `netstat` transport
fallback). The other 20 stop before behavioral execution without their
controllers and rest on frozen-candidate evidence. Their commands' sources did
not change after the freeze, apart from two `dns` changes that the DNS
rate-limiting evidence does not exercise.

Compared with the frozen candidates, seven topics change from FAIL to PASS on
both builds through fixes made after the freeze: `bashio` address checks,
`lsattr` attribute bits, `netstat` Unix sockets, namespace cgroup-v2 paths,
`sftp` binary transfers, `strace` attach and `tput` compiled terminfo. One
topic per build changes from PASS to FAIL: `fdisk` partition deletion on
static and the `rtspcat` output descriptor lifecycle on dynamic. Neither
command changed after the freeze. The `fdisk` case met a partition still held
by a udev probe, and the `rtspcat` fixture read an incomplete process-status
snapshot for its own before-and-after comparison. Each case passed three
repeats on the same binary; the recorded failures are kept.

The [validation record](data/release-0.1.3-validation.json) lists every case
whose result differs from the frozen candidates, with the product commits that
touch its command, every changed topic with its cause, and every ERROR. It
records the binary and manifest hashes, the harness and image-lock hashes, the
source changes since 0.1.2 and the evidence-only confirmation. The
[scope inventory](data/parity-0.1.3-scope.json) keeps missing commands,
unreviewed option forms and all deferrals visible.

## Follow-up topic resolution

The [topic-resolution record](data/parity-topic-resolution.json) adds ordinary
VM evidence for 38 of the 64 topics left unresolved by the release qualification.
The release binaries are unchanged. Of the original 600 topics, static now has
303 PASS, 271 FAIL and 26 UNRESOLVED; dynamic has 304 PASS, 270 FAIL and
26 UNRESOLVED. These counts summarize topics rather than additional passing
cases. The published release qualification above remains a historical record.

The follow-up runs exercise 106 ported cases on each build, together with 15
guest selfchecks, with no harness errors. Fixtures now receive a protected
namespace attestation, a loopback-only sysfs view and a bounded 64 MiB memlock
limit. The PTY driver retains input bytes and output chunks, observes requested
foreground ownership and restoration, replays primary-screen characters,
reverse bits and cursor, and compares timed redraws with independent FIFO reads.
The clock injector uses exact binary hashes and verified call sites for the
release builds. Invalid controls remain incomplete evidence.

Fifteen remaining topics require the unavailable kernel authorization device.
Five need kernel clamp support, including four controller topics still awaiting
a helper port: a native util-linux control on the available guest receives
`Operation not supported` when setting clamps on its own child. The other six
retain the hardware or interface limits listed in the obligation ledger.
