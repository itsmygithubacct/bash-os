# Historical deferral review

Migration work is in progress. The original 600 scenarios are preserved in the
[obligation ledger](../tests/parity-vm/deferrals.json), together with their
reviewed requirements, evidence links and specific remaining gaps. The
[execution review](data/parity-0.1.3-deferrals.json) reconciles those links against
saved static and dynamic VM runs. The initial qualification tables in the VM
guide describe the earlier fixture set.

The current review covers 406 of the 600 topics on both builds: static 213 PASS / 193 FAIL;
dynamic 214 PASS / 192 FAIL. The other 194 retain unresolved requirements: 99 have partial
coverage and 95 have none. These are topic counts, not additional behavioral test results.

The syslog review adds bounded three-record FIFO observations for startup, SIGHUP and periodic replay on both builds. Sender attribution is inferred from pinned serial source and isolated networking; HUP was queued while the daemon was stopped.

The broker review includes bounded default and 250 ms idle observations. Nominal durations fall within the measured brackets; strict nominal lower bounds and a 60,000 ms idle wait were not measured. Both builds also preserved four distinct blocks across partial writes.

The SQLite review records a locking failure on both builds: the second candidate writer began while the first held its transaction. The explicit no-locking case passed. These observations do not establish concurrent-commit behavior or a numeric candidate SQLite error code.

The scrub review adds seeded history pruning, explicit dropped counts, exact prompt-command restoration and private-history observations on both builds. Earlier reached failures remain visible. PTY writes establish delivered input; exact application read syscalls were not traced.

The DNS review adds the missing response-rate-limit slip observation. Received truncated replies and server counters support the bounded result; packet ingress and ordering were not independently traced. Earlier zone-selection, TSIG and DoH failures remain visible.

The mlock invalid-input review verifies nonzero status and stderr for all six cases on both builds. Existing invalid-input evidence remains, and this does not establish the separate all-operation requirements.

The watch error review records early exit on both builds before the interactive prompt and key handling. The candidate failures retain the ptrace timing qualification; the reference waits and exits after a key. [Detailed scope](watch-terminal-error-evidence.md) explains the bounded acceptance.

The top review records missing sort prompts on both builds, with later sort input unreached. Delay input and three FIFO redraw samples passed. The redraw interpretation is source-bound; timeout cleanup does not establish a natural-exit or terminal-restoration failure. Paired frozen `--once` captures add partial observations of load, displayed process count and memory/swap fields; uptime, aggregate CPU, broader task counts, `-b`/`--batch`, sorting, PID ties and row caps remain unverified.

The namespace review completes mount operations using native controls, recorded mount options and file effects inside a mapped user namespace. Bind-remount flags are source-bound. Future PID/time observations and the repeated PID request add partial unshare coverage; its other gaps remain.

The LPR and LSOF review completes three topics. Cancellation passes with signal observations bounded to six monitored syscall forms during the filtered process lifetime. Explicit file and stdin submissions retain exact backend arguments and bytes; bare-form submission failures remain. LSOF adds exclusion of a visible witness owned by another UID. Earlier submission and filtering failures remain FAIL on both builds.

The clock review includes synthetic returns injected at compiled callsites;
these observations do not establish what the kernel, vDSO or libc returned.
The future-fraction case expected `-0.100000000` and failed on both builds,
which printed `-1.900000000`. The `now-clock-error` case is a supporting
control and is not counted as requirement evidence.

The hwclock effects review records positive and negative drift correction and fractional remainder handling on both builds using a synthetic RTC. It also adds partial system-to-RTC and failure-path evidence. System time is bracketed; RTC and clock effects are synthetic. Injected close EIO skips the real close and does not establish descriptor cleanup after a real close failure.

The hwclock calendar review verifies raw display and UTC conversion for fixed synthetic RTC inputs on both builds. Malformed adjtime inputs were rejected before RTC open; valid LOCAL, mode-line whitespace and missing-file defaults remain partial. The RTC and clock replies are synthetic and do not establish physical RTC or system-clock changes.

The SU review adds absent-device fail-closed and injected fork/wait error observations on both builds. The no-exec observer acknowledges a non-dumpability request without applying it; the owned-child reap establishes collection, not a successful child operation. Earlier SU evidence remains.

The namespace review adds six separate native controls supporting the existing unshare inode comparison; no simultaneous six-namespace invocation is claimed. Unsupported-namespace EINVAL remains unobserved.

The UCLAMP follow-up adds builtin dispatch, owned-task queries and bounded three-TID preflight observations on both builds. The static all-tasks poweroff request remains 255 under its exact lifecycle disposition; its SSH failure cause is unobserved. Earlier setter gaps and failures remain.

The strace summary review checks both `-c` and `--summary` against a fixed x86_64 syscall sequence. Direct execution and a separate native ptrace observer verify the tracee before each case. Both frozen builds suppress per-call records and report one call for each of four syscalls, with one `openat` error. Timing columns are not compared, and these observations do not validate later source repairs.

The strace execution review records two failures on both frozen builds: an exec event splits a syscall record across physical lines, and `write` displays its buffer address instead of quoted data. Exit-status propagation, output-file routing, preserved stdout and named/numeric syscall filters pass. Every trace event is accounted for; semantic assembly supports those independent properties while the original physical-line failure stays visible.

The strace child-follow review checks one owned fork in both modes on each frozen build. With `-f`, tagged child calls are present; without it, the complete trace contains parent records only. Direct and native controls establish each invocation, and the raw audit verifies unique result attribution, child exit before reaping, ECHILD on a second wait and parent status 42. Physical-line failures remain separate observations; no GNU output or general signal-delivery parity is claimed.

The ncdu boundary review checks both `-x` and unrestricted traversal in a private user and mount namespace. Both builds count only local allocated blocks with `-x` and include the nested filesystem without it. Independent file accounting, GNU du and per-invocation metadata and traversal controls qualify the observations. Raw inotify records observe successful opens/accesses on two watched directories in the quiescent guest; they do not attribute events to a PID or observe failed opens and arbitrary metadata probes.

The killall5 dry-run review checks read-only target selection in a confined synthetic proc tree on both builds. The seven cases cover session and self exclusion, empty command lines, omit lists, malformed or disappearing entries and exit statuses. A live supervisor witness binds the nonleader caller to its actual session. Signal-denial controls protect the fixture; they do not establish signal-delivery behavior or a complete syscall trace. The disappearance case exercises one bounded schedule.

The SFTP navigation review adds complete native BASHSSH1 request and response frames for the selected-directory listing, checked against a tree-backed OpenSSH control on both builds. Escaped paths pass; quoted cd sends a malformed command and still fails. The quoted case never reaches the intended listing. Earlier session evidence remains, while binary upload/download gaps are unchanged. These local fixture transports do not establish SSH authentication, encryption or path confinement.

The Bash I/O network review exercises address and route operations inside a mapped network namespace, with independent native controls, complete marked ioctl traces and before/after snapshots. The route cases pass. A malformed mask is rejected only after the address ioctl succeeds and changes the interface, so the original validation-before-ioctl requirement fails on both builds. The historical note describing partial mutation is retained alongside that literal requirement; it does not turn the failure into a pass. Earlier setup errors remain unqualified.

The strace attachment review observes both existing threads attached before release on each build, followed by a worker held in a candidate-owned tracing stop for more than four seconds. The later stall remains FAIL and does not negate the earlier attachment observation. Fixture completion after killing the tracer does not prove natural exit under tracing. Raw case failure labels also appear on their linked requirements; the assertions distinguish the observed phases.

The PTY broker history review preserves the exact successful raw-history case and its pinned helpers. Both builds return the fixed raw bytes, deliver only subsequent output to a late attachment, and report matching attached/gap offsets. Other lifecycle cases remain unresolved: a possible descriptor collision prevents attributing an observer receive failure to the product, and the cleanup observations do not establish descendant reaping before builtin return.

Paired frozen PTY captures add partial attribution for child exit/cleanup and role/handle scope. They preserve 31 fixed output bytes before the exit event, native and candidate status 37, and a later `running=0` status. Cleanup shows only the later absence of one owned child after a successful terminate call. One observe attachment receives the fixed 32,813-byte stream at contiguous offsets. Descendant reaping before return, broader child cleanup, controller permissions, observer limits, detach, stale handles and cross-process scope remain unverified; both topics remain unresolved.

The process-record review adds seven paired observations for malformed stat records, a PID disappearing after enumeration, empty lists, counter rollback, guest accounting and new/reused PIDs. All pass their bounded predicates. Malformed status and cmdline behavior remains untested, so the original topic stays partial. The native guard descriptor and group-anchor cleanup are source-bound; offline parser checks reconstruct the pinned inputs from source rather than claiming those bytes were retained by the guest.

The password-prompt review adds synthetic set-success and confirmation-mismatch observations, including unchanged account files on rejection and exact terminal restoration after natural exit. Earlier EOF/EIO evidence remains. Echo during successful or mismatched reads and Ctrl-C restoration are still unqualified. The change-prompt case has a synthetic-input substring collision with the prompt itself; its raw failure is retained without attributing it to the product, and that case is excluded from the published runnable subset.

The DHCP server review adds offline subnet selection by giaddr, verbatim option 82 echo, persisted commit leases and commit-hook behavior. Failing or missing hooks preserve the complete ACK reply. Both builds omit the label-length byte in PXE menu suboption 9, which remains FAIL. Negative-vendor next-server gating, live serve exchanges, DECLINE/RELEASE, relay delivery and proxy sockets remain unresolved; these partial topics are not counted as full migrations.

A historical case becomes `MIGRATED` only when every requirement has an explicit
assertion and valid execution evidence on both builds. Its replacement cases
remain ordinary behavioral results. `MIGRATED` is an index entry, never another
passing test. A demonstrated candidate failure can retire an unexecuted
scenario; the failure stays visible. An invalid reference, missing execution,
skip, changed fixture or partially covered requirement cannot retire it.

The remaining entries distinguish missing fixture work from concrete limits.
Examples include unimplemented protocol peers, privileged block-device setup,
optional builtins absent from these builds, and NUL input that a shell-word-only
interface cannot represent. A private PTY, loopback socket or owned child process
is already available; needing one is no longer a reason by itself to defer work.

Each ledger entry retains its original purpose and reason, so changing the
description cannot silently narrow a compound scenario. Current reasons replace
historical claims about unavailable VMs or permission to use isolated fixtures.
Coverage labels describe asserted requirements, not the presence of a `covers`
annotation or a related smoke check.

Validate the ledger without executing a candidate:

```sh
python3 tests/parity-vm/deferrals.py
```

Reconcile it with private raw evidence:

```sh
python3 tests/parity-vm/deferrals.py --evidence evidence-config.json \
  --output deferral-results.json
```

The configuration names the static and dynamic binaries and the exact run,
group and case selections to use. Repeated attempts replace earlier records;
ambiguous duplicate selections are rejected. Reconciliation checks candidate
and payload hashes, completed VM provenance, guest identity, absence of shared
host mounts, the network canary and overlay disposal. The report records hashes
of the summary, provenance, payload and raw evidence for every selected run.

Fixture definitions are compared with the definitions saved in each payload.
Shared fixture helpers declare `helpers_sha256`; their contents are checked both
in the checkout and in archived payloads. Normative references pin their evaluator
and data files. Old passing evidence cannot qualify a changed definition.

Keep raw archives, transport credentials and guest disks outside the checkout.
The public review contains references and hashes, not those private artifacts.
