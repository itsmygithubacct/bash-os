# Payload completion review

This review starts at `9e74770ea97d5962d0bd4140552990a68553e37a`, which
contains the predecessor implementation in `fef28a92cc4461f98a3d84bea15fb54ac57c2a55`
and its bounded line-reader correction in
`d69e581c54d99a2fa0dbf23056de130021a61059`. The predecessor result described
85 original checks and measurements made before that parser correction.
An independent build of the inherited code passes all 90 current inherited
checks. The expanded 105-case suite exposes nine failures in that build.
The final suite passes **107/107** checks both natively and with the production
payload module instrumented by ASan/UBSan.

## Corrected behavior

* A rollback may remove every package belonging to its transaction. `remove`
  now reads all requested transaction references before invoking the helper,
  then invokes it once per distinct transaction in argument order. Duplicate
  package names and shared transaction IDs reuse that result. A failed
  transaction is not retried implicitly, later distinct transactions are
  still attempted, and the first failing helper status is returned.
* Installed state must resolve to a regular file. Directories and FIFOs do
  not count as installed packages. State reads open with `O_NONBLOCK` and
  check the opened descriptor as well, preventing a substituted FIFO from
  blocking the shell. INDEX must also resolve to a regular file and is opened
  without waiting for a FIFO writer.
* INDEX metadata containing terminal control bytes (other than the supported
  whitespace delimiters) is rejected, including escape and DEL bytes. Such
  records cannot authorize an install or emit escape sequences in inventory.
* Constructed INDEX and state-directory paths are allocated to their complete
  length; they are never silently truncated to a fixed buffer. The operating
  system still enforces its path limits.
* Inventory rows use the existing per-invocation `bl-output.h` buffer. This
  batches pipe/file writes while preserving newline flushing on terminals and
  without changing Bash's stdio settings. Output errors still fail the command.

All previous assertions remain. The recording helper now supports shared
transactions and removes all state records belonging to a rollback. Additional
checks cover quoted helper filenames, literal shell syntax in transaction IDs,
non-executable interpreters, duplicate transaction lines, 255-byte IDs, a state
file without its final newline, removal without an INDEX, and output failure
after rollback.

## External helper contract and limits

The full contract remains in [opus-payload.md](opus-payload.md). `bl-pkg.sh`
belongs to the bashy.box image and is absent from this repository. It is a
readable Bash script, so lack of execute permission is supported. The boundary
is still:

```
$BASH INSTALLER --internal --root ROOT --repo REPO --allow-unsigned install NAME...
$BASH INSTALLER --internal --root ROOT rollback TXN
```

Each item is one literal argv element; no command string is evaluated. Install
uses one helper invocation for all names after validation. Remove now uses one
invocation per distinct transaction, with its names resolved before mutation.
Successful removal messages describe the requested names; rollback can affect
other packages in the same transaction. These operations are not atomic across
distinct transactions. The helper owns archive extraction, transaction storage,
rollback implementation, dependency handling, and any transaction locking.

`PAYLOAD_REPO`, `PAYLOAD_ROOT`, and `PAYLOAD_INSTALLER` select the private
fixtures. The real image helper and real package archives are outside this
software-boundary qualification. The repository, state, interpreter and helper
are trusted local inputs, not a security boundary against concurrent hostile
writers or symlink changes. Regular-file symlinks are still followed. Installs
remain explicitly unsigned (`--allow-unsigned`); use `pkg` for signed mirrors.
No host installation is used by these tests or measurements.

## Reproduction

Build selection is `--include payload`; there are no companion loadables.
The default `_jsmn` helper selection is unchanged. `child-wait.h`,
`command-run.h`, and `bl-output.h` are used unchanged; this work requires no
shared helper edits.

```
python3 "$GATE" build -- ./build.sh --include payload --name sol-payload-final
python3 tests/opus-payload-installer.py out/bash-sol-payload-final
python3 "$GATE" build -- tests/opus-payload-build-sanitizer.sh "$EVIDENCE/sanitize"
python3 tests/opus-payload-installer.py out/bash-sol-payload-final \
  --module "$EVIDENCE/sanitize/payload-sanitize.so" \
  --asan-runtime "$(cat "$EVIDENCE/sanitize/libasan.path")"
python3 "$GATE" bench -- python3 bench/sol-payload.py \
  --binary out/bash-sol-payload-final --output "$EVIDENCE/bench-final.json"
```

`GATE` is the campaign's `scripts/gated.py`; `EVIDENCE` is this task's private
output directory. Build and benchmark commands must use their respective gate.
The correctness suite compiles nothing and uses an empty command PATH. Its
helper calls `/usr/bin` or `/bin` only to delete fixture-owned state files.
The sanitizer module instruments the production payload implementation; the
host shell and external helper are not wholly sanitizer-instrumented.

## Measurement method

`bench/sol-payload.py` retains the historical parsed inventory work unit:
20,000 INDEX records (1,696,256 bytes), 2,500 installed-state files, and 20,005
output lines per pass, with 40 passes per sample. A Python-generated exact
table is the independent output oracle. The helper workload uses 20
install/remove pairs on the last record of a 2,000-record INDEX, yielding 40
helper executions. Every helper argv and the final empty state are checked.
The fake helper's contents and INDEX hashes are recorded.

Each workload has one warm-up and seven timed samples. Every command must
succeed, and every repeated pass's output must match. Invalid samples receive
no timing distribution. The process affinity is fixed to one recorded CPU,
and reports include source/binary/harness hashes, versions, work counts,
fixture hashes, reset rules, and all validation statuses. Measurements include
shell startup and captured output, with validation outside the timer. There is
no equivalent external payload implementation, so results are self timings
with no external ratio. They do not measure extraction of real package data.

## Results (2026-10-20)

Native and ASan/UBSan runs each passed 107/107 checks. The inherited binary
passed its original 90/90 checks but only 96/105 in the expanded regression
run, including three bounded FIFO timeouts. Those failures are retained in the
receipt; they are not skips. The final two output-buffer assertions pass in the
107-case suite. The final sanitizer build reports only unused static functions
from unchanged common headers.

Timings below were collected sequentially in one benchmark-gate session on an
Intel Core i7-9850H, Linux 6.12.111, CPU affinity `[11]`, Bash 5.3.15 and GCC
14.2.0. All eight batches per case (warm-up plus seven samples) passed their
independent oracles. Before/after fixture, initial-state, expected-output,
helper and harness hashes match.

| Work per sample | Inherited median ms (range) | Final median ms (range) |
|---|---:|---:|
| 40 complete inventory listings | 4908.3 (4365.5–5093.1) | 1825.0 (1663.0–1986.3) |
| 20 install/remove pairs | 136.9 (130.4–160.8) | 152.9 (137.7–171.2) |

The inventory median is 62.8% lower in this same-session comparison. Validated
single-pass syscall profiles show **20,005 → 24 writes**, with the same
20,002 `newfstatat` calls and byte-identical output. The original write calls
accounted for 22.85% of traced syscall time; the final profile spends almost
all its syscall time probing installed state. No further optimization of those
required state probes is claimed. Traced timings include tracing overhead and
are separate from the untraced sample distributions.

No helper speedup is claimed. The initial independent baseline's transaction
median was 164.0 ms and its inventory median was 4289.6 ms; the variation across
runs is why the table uses one gate session and why these figures are not
compared with historical results from other builds. The paired runs were
sequential, not randomized, and other host activity can still affect them.

| Artifact | SHA-256 |
|---|---|
| Inherited source | `701dcf04e38cfe4b32790bfc79443681456c54aa7447a4a8c50277fdde24bf5b` |
| Final source | `bcc5553a283259b8f47095b5de811b338d10d1bf8fec6ad066ddf3b071152c51` |
| Inherited binary | `211af960aaa5a550ef9016cb3dc21acc148909d68f2c5be133e7d12dcd2777e5` |
| Final binary | `f9abb957685cf90457a5fd83f0c4d8c091827d5dceb341861eb20cede743a281` |

Raw reports are preserved as `bench-before.json`, `bench-paired-before.json`,
`bench-paired-final.json`, and `profile-{before,final}.{json,txt}` in the task's
evidence directory, with exact commands and log paths in `result.json`.
Historical reports and shared benchmark/catalog files were not modified.
