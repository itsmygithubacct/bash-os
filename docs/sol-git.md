# Matched Git workloads

`bench/sol-git.py` adds a bounded performance and correctness workload for
`init`, `status`, `diff`, `log`, `add`, and protocol `clone`. It supplements
the 69 parity scenarios, malformed-storage checks in `tests/git-integrity.py`,
and patch path/preflight checks in `tests/git-apply-paths.py`.

The new workloads need `git`; the storage integrity suite also needs `obj`
and `index`. The full parity scenarios use native fixture utilities with an
empty PATH. The validation selection is:

```sh
./build.sh --include git,obj,index,pack,cat,chmod,cp,ln,mkdir,mv,rm,rmdir,sed,sleep,wc,head,cut,sort,tr --name sol-git --no-strip
```

This includes `_git`, `_sha1dc`, and `_monocypher` and links zlib. Campaign
builds and measurements must use the campaign resource gates.

For correctness only, run:

```sh
python3 bench/sol-git.py out/bash-sol-git --check-only --output /tmp/git-check.json
python3 tests/sol-git-lifecycle.py out/bash-sol-git
python3 tests/sol-git-oracles.py
```

For measurements, omit `--check-only` and use at least seven samples, after
the harness's one warm-up. The default scales are 100 files/10 commits,
1,000 files/100 commits, and 4,000 files/400 commits. Each has an additional
tracked history file. A pass launches the same selected Bash executable
on both sides and executes one command, using either `builtin git` or
the absolute system Git path.
Both implementations receive fresh, independent repositories on every pass;
setup, validation, and cleanup are excluded from elapsed time. Fixtures are
warm in the filesystem cache. System Git refreshes each index before the
deterministic working changes are applied. Initial file mtimes are pinned
to 1750000000, outside the same-second racy-index window, so unchanged
files can use the stat shortcut on both sides. Implementation order
reverses between passes.

An explicit private template contains only the description and commented
exclude file that the builtin creates. `init` must create exactly the same
four metadata files and eight directories on both sides; system sample
hooks are excluded from this work unit. Both metadata bytes and directory
membership are checked.

Python constructs Git blob, tree, and commit records and computes their IDs.
File contents, identities, dates, history shape, modes, and options are fixed.
The fixture digest includes every initial object ID and byte. Ten percent
of numbered files receive one appended line, the last five percent of
tracked paths are deleted, and one untracked file is added. `status` uses
`--porcelain=v1 -uno`, `diff` uses `--numstat --no-renames`, `log` prints
full commit IDs, and `add -A` stages all changes.

Each pass requires the expected exit status, stdout, and stderr. System Git
reads the resulting index, HEAD, and tree; the index must contain exactly
the independently calculated modes, IDs, stages, and paths. Every object,
including historical trees, is enumerated and read back with `cat-file
--batch`; both membership and every byte must match. Added trees must equal
the independently computed tree ID. Working file contents and absence of
leftover locks are also checked. Failed cells make the driver fail and are
recorded in the JSON report; a driver exit alone is insufficient evidence.
`tests/sol-git-oracles.py` checks the oracle itself: deliberate changes to
file bytes, executable modes, object membership, object bytes, index modes,
and HEAD must each be detected, followed by a clean-state check.

Clone uses an injected SSH pipe transport to the same real system Git
`upload-pack` server for both clients. This runs production protocol paths
without requiring a network or SSH daemon. Both source stores are private,
freshly materialized copies. Destination objects must arrive in packs,
must have link count one, and must use no alternates. A strict reference
`fsck` runs after each clone. These measurements cover the clients and a
common server; they do not measure SSH encryption or network latency.

JSON reports retain each wall-time sample in milliseconds, per-process
peak RSS from Linux `wait4` in KiB (maximum of shell and waited descendants),
user/system CPU time, and stored `.pack` bytes excluding `.idx` files.
They also record CPU affinity, versions, work counts, fixture hashes, and
source/binary SHA-256 hashes. Setup and oracle memory are outside the
measured child. Ratios apply only to these validated, matched work units.

`tests/sol-git-lifecycle.py` makes 720 Git calls in a persistent shell,
including failed protocol helpers, blocked config writers, and invalid commands, interleaved with
owned background jobs. It checks parent descriptors, signal masks/handlers,
cwd/environment, unreaped children, lock cleanup, and exact repository
state. It also sends five blob sizes to `/dev/full` to check write-failure
status propagation.

The scope is these workloads and the existing focused suites. It does not
establish full Git compatibility, real-network performance, cold-cache
performance, or performance on other hosts.

Reference oracle controls passed at 100 files/10 commits, 1,000/100,
4,000/400, and 100/5,000, including protocol clone and six deliberate
corruptions. Native validation and measurements remain pending: the
mandatory campaign resource gate did not admit the build during this run.
No performance ratios are established by this change.
