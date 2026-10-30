# ncdu boundary: proposed primary evidence gate

This is a data-only specification for an independent primary-owned gate. It is
not executed by the fixture or the shared runner, does not change runner labels,
and has not been applied to any result. Apply it separately to each build and
each case, before treating a result as evidence. The original requirements are
that `-x` does not descend across the different-device boundary and that the
unrestricted traversal counts the nested filesystem. Quiescent, isolated guest
execution is required because inotify events are not attributed to a process.

The gate produces **UNQUALIFIED**, **OBSERVED-FAIL**, or **QUALIFIED-PASS**.
UNQUALIFIED is an evidence/infrastructure classification, not a product
failure. It does not alter the runner's raw ERROR/FAIL/PASS label. When evidence
is incomplete, do not infer a product verdict. When intact controls and a
complete candidate observation establish a mismatch, retain it as an observed
product failure even if the later verifier itself also failed.

## Binding and capture envelopes

1. Bind the run ID, guest identity and quiescence/cleanup evidence, exact case
   ID and mode (`migration-ncdu-boundary-reviewed-x` = `x`, `...-full` =
   `full`), frozen candidate SHA-256, exact suite bytes and suite SHA-256, and
   both actual helper bytes and hashes to the primary evidence bundle. Verify
   the helper hashes against the selected case's `helpers_sha256`, including
   this gate specification. Do not combine artifacts across cases, builds,
   sides or invocations. The guest setup runs the guarded candidate inside the
   fixture namespace; the later candidate-side script only verifies the files.
2. Require the complete guest `candidate.json` result and raw runner case
   result, including setup and verifier process records. Preserve their bytes
   and compute SHA-256 for each. For both process envelopes require `error` to
   be null, no stray processes, valid base64 stdout/stderr, and
   `captured_bytes` equal to the total decoded byte count. Setup must exist and
   have status zero; absence of the guarded setup, an execution/timeout error,
   nonzero setup status, or `harness_error` is UNQUALIFIED. A later verifier
   envelope error, timeout, or stray process also makes the run UNQUALIFIED.
   Preserve the raw status and stdout/stderr even if the gate's verdict differs.
3. For a successful setup require all 16 diagnostic records named in the
   selected suite case: `ncdu-boundary-setup.out`, `.err`, `.status`,
   `ncdu-boundary-mount.out`, `.err`, `.status`, `ncdu-boundary-du-x.out`,
   `.err`, `.status`, `ncdu-boundary-du-full.out`, `.err`,
   `ncdu-boundary-observer.json`, `ncdu-boundary-control.json`,
   `ncdu-boundary-candidate.out`, `.err`, `.status`. Here abbreviated suffixes
   retain the immediately preceding prefix. Each diagnostic envelope must be a
   regular captured record with valid base64, no missing/error indicator,
   `truncated` exactly false, and `captured_bytes` equal to decoded length;
   empty stderr/stdout is valid where specified. Compute a SHA-256 over every
   decoded diagnostic and store the name, length and digest in the primary
   evidence manifest bound to the raw `candidate.json` digest. Hashes are
   evidence bindings, not a claim that unrecorded source data existed.
4. For a failed setup, retain its process envelope and every diagnostic that
   exists; mark missing later-stage records as not reached, rather than
   demanding files from stages that did not start. A missing/error/truncated
   record for any reached stage and every failed setup is UNQUALIFIED. No raw
   runner classification or successful unrelated invocation cures it.

## Setup and native controls

Parse JSON strictly, rejecting duplicate keys and invalid types. Require setup,
mount and `du-x` status files to be exactly `0\n`; require empty `du-x.err` and
`du-full.err`. `control.json` must match the case mode and have
`parser_selftest: "ok"`, six expected fixture stat records, inner and outer
user/mount namespace identities that differ, and one private tmpfs mountinfo
entry for `/tmp/parity-case/tree/foreign`. Check the original fixture conditions:
root/local device equality, foreign root/deep/payload device equality and
foreign device inequality, directory and regular-file modes, one link on the
two regular files, sizes 8192 and 32768, positive payload blocks, foreign root
zero blocks, and nonzero foreign total. The successfully completed guest setup
and identity guard attest the fixture contents and mapped credentials; these
are not new independent host observations.

Recompute `one` and `full` from each path's `blocks * 512`, including directory
blocks, and require exact equality to the report. Parse native du outputs as
nonempty, newline-terminated unique ASCII `<digits>\t<path>` directory records.
Require `du-x.out` to equal `one`, optionally with only `tree/foreign` = 0;
require `du-full.out` to equal `full`. Any control parse, mismatch or failed
native operation is UNQUALIFIED, never a candidate mismatch.

## Observer records

Require observer version 1 and matching mode, with exactly three named records:
`metadata-only`, `native-traversal`, and `candidate`. Each must have state
`complete`, `complete: true`, and no error, observer_error or partial record.
For each record require exactly two distinct watch descriptors, serialized as
decimal string keys in `watches`, mapping to `foreign` and `foreign/deep`,
identity objects with matching integer descriptor, device
and inode from `control.json`, and complete `fdinfo` for those descriptors.
Reconcile the inotify entries in fdinfo with those descriptor, inode and device
identities using the guest Linux fdinfo encoding; if the encoding or identity
cannot be established, the record is UNQUALIFIED. No watch may be inferred from
a different observation. Descriptor numbers may be reused in different fresh
inotify instances.

For Linux fdinfo, parse each `inotify wd:<hex> ino:<hex> sdev:<hex>
mask:<hex> ignored_mask:<hex>` line, allowing other fields and unrelated fdinfo
header lines. Require exactly the two recorded watch descriptors, inode equal
to the corresponding decimal `ino`, `ignored_mask` zero, and `mask` containing
both 0x01 and 0x20. The kernel `sdev` is `(major << 20) | minor`, using the
Linux major/minor decoded from that path's `st_dev`; reject values outside the
kernel's 12-bit major and 20-bit minor representation. Do not compare the
encoded `sdev` integer directly to the userspace `st_dev` integer.

Decode each `raw_base64` strictly and require its length to equal `bytes` and
be at most 32768. Independently parse all Linux inotify records as native-endian
`iIII` headers plus their declared name bytes, including NUL termination and
padding; require a complete stream, known watch descriptors, and exact equality
with each stored parsed event's watch name, wd, mask, cookie and base64 name.
Reject watch loss (`IN_UNMOUNT`, `IN_IGNORED`), `IN_Q_OVERFLOW`, unexpected
event types, truncated records, malformed names, or any disagreement as
UNQUALIFIED. `IN_ISDIR` may accompany `IN_OPEN` or `IN_ACCESS`. Record the raw
bytes' SHA-256 for each of the three records in the bound primary manifest.

For `metadata-only`, require returncode 0, empty stderr, stdout exactly the
foreign root's decimal `dev:ino\n`, and no watched `IN_OPEN` or `IN_ACCESS`.
For `native-traversal`, require returncode 0, empty stderr, its decoded
stdout/stderr byte-identical to the respective du-full diagnostics, and at
least one direct `IN_OPEN` (empty event name) on each watched directory. These
are sensitivity and negative controls for this invocation; their failure is
UNQUALIFIED.

## Candidate assessment

Parse `candidate.status` strictly and require it to equal the candidate
observer's outcome exactly. Require an integer positive PID, `group_empty`
true, a boolean timeout, and a coherent status: without timeout an integer
returncode; with timeout a null returncode and integer `reaped_returncode`.
For `out` and `err`, require the recorded capture byte count and SHA-256 to
match the corresponding decoded diagnostic, and `limit_reached` to be a
boolean consistent with the 262144-byte per-stream limit. If either stream
reaches the limit, its completeness is ambiguous: classify UNQUALIFIED. The
primary manifest includes these hashes as well as all other diagnostic hashes.

Only after all infrastructure and control checks succeed, independently assess
the complete candidate observation. A nonzero candidate return, candidate
signal, or candidate timeout is OBSERVED-FAIL. A nonempty stderr is
OBSERVED-FAIL. In `x` mode any watched `IN_OPEN` or `IN_ACCESS`, including
named child events, is OBSERVED-FAIL. In `full` mode a missing direct `IN_OPEN`
on either watched directory is OBSERVED-FAIL. Parse candidate stdout with the
same unique, complete ASCII listing grammar used for the native controls;
**complete but empty, malformed, non-ASCII, duplicated, or missing-final-newline
candidate output is OBSERVED-FAIL**, not a control error. Compare exact paths
and allocated totals with recomputed `one`/`full`, allowing only the optional
zero `tree/foreign` row for `x`; mismatch is OBSERVED-FAIL. A scan that
traverses and then hides the foreign rows still fails the `x` event assertion.

If no product mismatch is found, require the later verifier to have status 0,
empty stderr and stdout exactly `ncdu-boundary-<mode>-verified\n`; otherwise
classify UNQUALIFIED. If the independent product assessment already establishes
an OBSERVED-FAIL from complete valid records, do not discard it merely because
the verifier returned nonzero or emitted its mismatch diagnostic. Preserve its
raw envelope for review. No qualification is possible when any earlier binding,
capture, control or observer check fails.

This observes successful directory opens/accesses on these two inodes; it is
not a syscall-complete trace. Failed opens and direct metadata-only probes of
guessed descendant names are not observed. Guest capability and event behavior
must be established by primary-owned execution; no result is claimed here.
