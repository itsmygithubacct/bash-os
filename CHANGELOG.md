# Changelog

All notable changes to bash-os are recorded here. Versions follow
[semantic versioning](https://semver.org/); `VERSION` holds the current one.

## 0.1.3 — Unreleased

- Added a disposable KVM test environment with pinned reference Bash, isolated
  terminal and loopback network fixtures, bounded execution, raw evidence and
  explicit lifecycle checks. The historical suites retain all deferred cases.
- Added independent Unicode 17 and published protocol/cryptographic vectors,
  plus a reproducible Bash and command interface inventory. The
  [parity scope](docs/parity-scope.md) documents the remaining coverage.
- `curl` sends nondefault ports in Host, handles repeated and file-based data,
  honors header overrides and silent errors, and follows redirect method and
  transfer-status behavior more closely. `dns` stops retrying a verified
  NXDOMAIN response.
- Expanded selected evidence to 893 modern fixtures plus 3,218 historical
  behavioral cases. Static results are 3,805 PASS and 283 FAIL; dynamic results
  are 3,803 PASS and 285 FAIL. Both retain 23 optional skips and zero selected
  harness errors. The deferral review records 252 migrated topics and 348
  unresolved topics; migration remains in progress. Topic metadata adds no passes.
- Independent data checks execute 9,331,283 planned assertions per build, with 40
  retained NFC/NFKC composition-exclusion failures. See the
  [validation record](docs/data/parity-0.1.3-validation.json) for separate
  parity/contract counts, fixture revalidation, evidence hashes and exclusions.
  These additions do not establish complete Bash or command parity.

## 0.1.2 — 2026-10-26

- `bc` now treats bare operands as filenames and uses GNU's success status
  after recovered syntax or runtime errors in ordinary stdin/file runs.
  Use `-e EXPR` for argument expressions and `-f -` for explicit stdin.
  Existing `-e`/`-f` forms and the new `--strict-errors` option retain status 1
  after language errors. File, I/O and reported resource failures still fail.
- `git cat-file` distinguishes unresolved names from missing full object IDs
  across its type, size, existence, pretty-print and explicit-type modes,
  including status and exact diagnostics.
- `strings` matches GNU's absent-file and non-directory-path diagnostics,
  including names containing spaces or quotes.
- Expanded isolated parity fixtures retain strict help/version and custom
  interface differences. A newly exposed `bc` syntax-recovery output
  difference remains visible; this release does not claim complete GNU parity.
- Both Linux x86-64 builds have 3,171 passes, 24 retained failures, zero harness
  errors, 23 optional-module skips and 600 deferred cases across 3,818 cases.
  See the [0.1.2 validation record](docs/data/release-0.1.2-validation.json).

## 0.1.1 — 2026-10-23

A completion and hardening release, adding `bashclear` and conventional `clear`.
Existing loadables were brought up to documented contracts, with regression,
sanitizer and benchmark evidence. Every loadable now has at least smoke
coverage; none is left at build/help only.

### Added

- GNU command names `base64`, `sha256sum`, `gzip`, and `tar` in `core` and
  inherited profiles, with binary-stream comparisons, checksum verification,
  gzip cross-reader checks, and tar interoperability fixtures.
- A scratch Docker image and `scripts/bash-os-docker` working-directory launcher.
- A visible Bash/GNU parity suite comparing stdout, status, files, modes and links.
- 289 reviewed loadable suites with 3,806 cases, run through mandatory private
  namespaces and a restricted syscall filter. The static and dynamic builds
  each record 3,155 passes, 28 retained compatibility failures, 23 optional-module
  skips and 600 deferred cases after matching ACL reference checks. The
  overlapping focused regressions pass 2,076 checks; Docker passes 131/131.
  See [the validation record](docs/data/loadable-parity-validation-5.json).
- Published Linux x86-64 static and dynamic binaries with SHA-256 checksums,
  resolved builtin lists and build manifests.

### Compatibility fixes

- `cp -n` / `--no-clobber` preserves existing files and symlinks, including
  with `-f`; the last `-i` or `-n` controls prompting versus skipping.
- `touch -d @SECONDS` accepts signed epoch times and nanosecond fractions.
- `cat --` ends option parsing, with common GNU line/display options supported.
- Archive hardlinks and FIFO metadata, gzip link handling, base64 final groups,
  Unicode slicing, editor append behavior, terminfo extended names, and queued
  inotify events have focused corrections and regression coverage.
- File modes, ACL masks, formatting, option errors, exit statuses and selected
  ordinary-file disk-image operations more closely match their reference tools.
  Remaining strict differences are listed in the validation record; this is
  not a claim of complete GNU command compatibility.

### Terminal commands

- `bashclear` and `clear`: independent builtins included from `core` upward,
  with `-T`, `-x`, help/version, checked output, and a documented terminal
  table usable in static images without terminfo files. Captured host byte
  comparisons and private PTY tests cover screen/scrollback behavior, options,
  terminal errors and output recovery. See [clear](docs/clear.md) for the
  fixed-table and serial-padding limits.

### Loadable status

64 of the original 280 loadables moved to a stronger evidence level, including all 20
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
- When the byte after a declared name is not NUL, `index` lists the name
  with that byte and ends it there. Git copies the byte too but adds no
  terminator, so its listing runs on into memory it did not clear and
  varies by build.
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
