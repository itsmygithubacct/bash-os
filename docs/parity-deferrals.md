# Historical deferral review

Migration work is in progress. The original 600 scenarios are preserved in the
[obligation ledger](../tests/parity-vm/deferrals.json), together with their
reviewed requirements, evidence links and specific remaining gaps. The
[execution review](data/parity-0.1.3-deferrals.json) reconciles those links against
saved static and dynamic VM runs. The initial qualification tables in the VM
guide describe the earlier fixture set.

The current review covers 399 of the 600 topics on both builds: static 209 PASS / 190 FAIL;
dynamic 210 PASS / 189 FAIL. The other 201 retain unresolved requirements. These are topic counts,
not additional behavioral test results.

The syslog review adds bounded three-record FIFO observations for startup, SIGHUP and periodic replay on both builds. Sender attribution is inferred from pinned serial source and isolated networking; HUP was queued while the daemon was stopped.

The broker review includes bounded default and 250 ms idle observations. Nominal durations fall within the measured brackets; strict nominal lower bounds and a 60,000 ms idle wait were not measured. Both builds also preserved four distinct blocks across partial writes.

The SQLite review records a locking failure on both builds: the second candidate writer began while the first held its transaction. The explicit no-locking case passed. These observations do not establish concurrent-commit behavior or a numeric candidate SQLite error code.

The scrub review adds seeded history pruning, explicit dropped counts, exact prompt-command restoration and private-history observations on both builds. Earlier reached failures remain visible. PTY writes establish delivered input; exact application read syscalls were not traced.

The DNS review adds the missing response-rate-limit slip observation. Received truncated replies and server counters support the bounded result; packet ingress and ordering were not independently traced. Earlier zone-selection, TSIG and DoH failures remain visible.

The mlock invalid-input review verifies nonzero status and stderr for all six cases on both builds. Existing invalid-input evidence remains, and this does not establish the separate all-operation requirements.

The watch error review records early exit on both builds before the interactive prompt and key handling. The candidate failures retain the ptrace timing qualification; the reference waits and exits after a key. [Detailed scope](watch-terminal-error-evidence.md) explains the bounded acceptance.

The top review records missing sort prompts on both builds, with later sort input unreached. Delay input and three FIFO redraw samples passed. The redraw interpretation is source-bound; timeout cleanup does not establish a natural-exit or terminal-restoration failure.

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
