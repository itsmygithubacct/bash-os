# Changelog

All notable changes to bash-os are recorded here. Versions follow
[semantic versioning](https://semver.org/); `VERSION` holds the current one.

## 0.1.1 — 2026-10-22

A completion and hardening release. No loadables were added. Existing
loadables were brought up to documented contracts, with regression, sanitizer
and benchmark evidence. Every loadable now has at least smoke coverage; none
is left at build/help only.

### Loadable status

64 of 280 loadables moved to a stronger evidence level, including all 20
that had only build and help checks, which are now covered by a contract.
Status per loadable, with evidence and limits, is in
`docs/loadables-status.md` and `docs/loadables-status.csv`.

### Completed loadables

- **Text and data:**
  - bc: functions, control flow, `obase`, and files;
  - head;
  - grep with native PCRE2;
  - nl, join, fold, expand, unexpand, wc and diff;
  - pr: the GNU CLI and layout gaps, and streamed column pages;
  - sed: GNU regex dialects and BRE by default, `-z`, `--sandbox`,
    `--follow-symlinks`, directory-anchored `-i`, and the `e`, `v` and `z`
    commands;
  - tac: GNU's bounded read windows instead of mapping the whole file, a
    spool for pipes, and GNU regex separators;
  - expr: a guard against the glibc regex loop.
- **Editors and terminal:**
  - vi: counts, ex `:d` ranges, and UTF-8-safe visual endpoints;
  - nano: justify, spell check and word completion;
  - ts: incremental highlighting;
  - tui, buf and clip;
  - screen, more and top.
- **System and devices:** blockdev, uclampset, POSIX and SysV IPC, keyctl,
  rngseed, halt, poweroff, reboot, fsfreeze, losetup, mkfs (ext2), swapoff,
  hwclock, fstrim, dmsetup (mapper mutations over the DM ioctl ABI), setpgid,
  renice, killall, pgrep and pkill.
- **Network and services:** ping, netstat, ss, rtspcat, mail, rsync, cluster
  (authenticated loopback membership), bashlogger, bashsyslogd, sv, ptybroker,
  fifo, payload and zstd (bounded-memory streaming).
- **Authentication and printing:**
  - doas;
  - su;
  - lpr: a configured delivery backend and private spools;
  - sudo, including read-only `sudo -l` listing.
- **Development:**
  - the git storage and patch paths;
  - git index: listings match `git ls-files --stage` wherever git's own result
    is deterministic, for split, sparse and version-4 indexes too;
  - gpu frame oracles and driver fixtures.

### Hardening

- **Files and streams:**
  - cmp: short reads;
  - recursive copies: symlink replacement names are reserved;
  - mv: a move source is removed only after the copy is finalized;
  - split: input aliases;
  - dd: reblocking bounds;
  - diff: allocation failures;
  - descriptor ownership when stdin is duplicated.
- **Processes and signals:**
  - shell signals and exported state are preserved across process wrappers;
  - signal numbers and realtime names are validated;
  - sysctl honours ignore-unknown;
  - SIGCHLD traps are queued until `wait` returns.
- **Network:**
  - nc drains its streams completely and bounds idle sessions;
  - httpd frames responses exactly, rejects ambiguous requests, and matches
    multipart delimiters on complete lines.
- **Terminal:** vt bounds its terminal encoding.
- **Accounts and scheduling:**
  - user database records are kept whole and validated;
  - crontab publishes from exclusive private temporary files;
  - at queues complete, uniquely named jobs.
- **Crypto:** crypto handles are released on output failure.
- **Build and packages:**
  - cached build artifacts are validated before reuse;
  - build trees are relocatable;
  - package publication and rollback preserve unrelated files;
  - package indexes are verified against the published bytes;
  - unreadable revocations are refused.
- **glibc regex:** glibc's `set_regs` loops forever on some repeated groups
  that contain anchors and can match empty, for example `(|^b)+` on `.b`. sed,
  tac and expr now guard every multi-register search, so such a pattern gives
  GNU's result or a clear refusal and never hangs the shell. bash's own
  `[[ =~ ]]` uses the same glibc matcher and is unchanged.

### Build and CI

- GitHub Actions CI. Reference coreutils runs are held to their own release's
  skip statuses.
- The build falls back to the GNU mirror, with pinned hashes, when
  ftp.gnu.org is unreachable.
- Build manifests record the bash-os version (`bash-os X.Y.Z` in
  `.manifest.txt` and `bashos_version` in `.manifest.json`). A version change
  invalidates the build cache.

### aarch64 advisory: wrong P-256 results

GCC 14.2 miscompiles the portable 32x32-to-64-bit multiply-add in p256-m on
aarch64 at `-O2` and above: it drops the 16-bit masks, so high partial
products are counted twice. Every P-256 operation in an aarch64 build made
with that compiler was wrong. x86_64 and riscv64 are not affected.

- **Affected packages:**
  - `crypto_2026.09.15.1_aarch64.pkg` (sha256
    `15e5e037e50727fc63e4b5229ff1c960a255493958f1d5b5d5e9e333fe12310f`):
    `ecdsa-p256` key generation, public keys, PEM export, signing and
    verification, and P-256 certificates in `x509-chain-verify`;
  - `acme_2026.09.15.1_aarch64.pkg` (sha256
    `2981cd80da0cfe92493b35aaabc68f84a8aa11364b8d6ce6ac185c17fbb6f010`):
    ES256 account keys and request signatures.
- **Not affected:** package signatures, which use ed25519, and every other
  algorithm in `crypto`.
- **Fix:** p256-m computes the low-half product so the compiler cannot fuse
  it. A P-256 known-answer test runs in the cross smoke, and CI builds and
  tests aarch64.
- **What the affected builds did, as tested:** they produced wrong public
  keys, and signatures that no correct verifier accepts. Their verification
  rejected every signature tested, valid ones included, and they rejected
  valid ECDH peers and valid certificate chains. No forged or altered
  signature was accepted in the tested cases. These are bounded test
  fixtures, not a proof.
- **What to do:** on aarch64, treat any P-256 private key or ES256 ACME
  account key used with these packages as exposed: replace it, and discard
  its signatures. Their public keys and signatures came from broken
  arithmetic, and it has not been shown that they do not reveal the key.
  The release's security review could not settle the question either way. A
  model of the affected multiply reproduces the recorded broken public
  keys. Those points are not on the P-256 curve, so the usual hardness
  argument does not apply to them, and no way to recover the key from them
  was found. Not finding one is not proof that none exists, so the advice
  stands: treat affected keys as exposed.

### Security review

The release tree had a seven-pass review: memory safety, untrusted bytes,
shell lifetime, privilege and mutation gates, and path and helper
containment. Each repair has a regression test that fails on the reviewed
tree, and a sanitizer run.

- **nc:** a closed standard output killed the shell. nc now ignores SIGPIPE
  only while it writes to a non-socket, then restores the caller's
  disposition.
- **ptybroker:** a signal that arrived while a session was starting made
  `ptybroker create` fail with "Interrupted system call". Only that startup
  wait retries now; a trap still interrupts `ptybroker receive`.
- **pty, sv and git:** programs they started inherited a signal they had
  ignored for themselves. A `pty spawn` target, and an editor, bisect
  script or ssh transport that git ran, had SIGPIPE ignored, so a pipeline
  inside them reported broken-pipe errors instead of ending quietly. An sv
  service had SIGHUP ignored. Each now gets the caller's disposition back
  before exec.
- **pkg:** `pkg install` followed a symlink below `--root` and wrote the
  loadable outside the root, and legacy extract and `pkg verify` did the same
  for paths they create or read. A link below `--root` is now refused. The
  package file, a local source and the `--root` path itself may still be
  links. When the root is `/`, every link belongs to the administrator and
  is followed, as before.
- **cron:** `cron run --once` followed a symlinked spool, a world-writable
  spool and a symlinked `atjobs`, and it replaced a symlinked state file.
  The spool must now belong to its owner alone and must not be a link, the
  same rule lpr uses. `/etc/cron.d` and the output directory may still be
  links.
- **passwd:** `passwd info` showed an empty uid as 0. Only a decimal id is
  accepted now, as login lookup already required; a literal 0 is still root.

The review found no gap in doas, su, sudo, dmsetup, fstrim, blockdev,
fsfreeze, losetup, hwclock, bashclock, ntp or mail. Their tests inject the
credential check, ioctl, clock or SMTP answer. No live `/dev/bashos-auth`
authentication, host account change, block-device ioctl, freeze, discard,
clock step or mail delivery was performed. Each loadable's row in
`docs/loadables-status.md` says which real operation its suite leaves out.

### Known limits

- `sudo -l` reads the authority's policy with the caller's own credentials;
  a policy file the caller cannot read makes listing fail.
- sed refuses some repeated groups with anchors that GNU sed finishes,
  because glibc might not return on them. The refused shapes are listed in
  `docs/head-sed.md`.
- `tac -r` refuses a repeated group that can match empty and mixes `^`,
  `` \` ``, `\<` or `\>` with `\b`, `\B` or `\'` (for example
  `` \(\|\`b\|\bb\)+ ``), even where GNU tac finishes. It says the separator
  cannot be matched safely.
- `index` refuses three kinds of malformed index on which git's own result
  varies between runs or never finishes: an entry that runs past the mapped
  page, a two-word split bitmap that has already reached the shared index,
  and three untracked-cache shapes. They are listed in `docs/sol-index.md`.
  Its errors exit 1 where git exits 128.
- In an index file that is exactly one page, a name with no NUL that runs
  to the end of the file is listed up to the end of the file. Git reads
  past the page there: it measures a `0xFFF` name with `strlen`, and for a
  declared length it copies one more byte, the NUL it expects after the
  name. Git's own listing there varies by build.
- `index read` follows `git ls-files`: like git, an ordinary read does not
  verify the index's trailing SHA-1, so a damaged checksum still lists the
  entries. The checksum detects accidents; it authenticates nothing.
- pkg downloads with its curl builtin. If that builtin is disabled, pkg runs
  an external `curl` found through `PATH`; with an empty `PATH` that search
  tries the current directory, as bash's own command lookup does.

## 0.1.0 — 2026-09-23

Initial public release: GNU bash 5.3 with 280 loadables compiled in as
builtins, selectable build profiles, static and dynamic builds, and signed
packages.
