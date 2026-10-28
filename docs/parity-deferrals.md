# Historical deferral review

Migration work is in progress. The original 600 scenarios are preserved in the
[obligation ledger](../tests/parity-vm/deferrals.json), together with their
reviewed requirements, evidence links and specific remaining gaps. The
[execution review](data/parity-0.1.3-deferrals.json) reconciles those links against
saved static and dynamic VM runs. The initial qualification tables in the VM
guide describe the earlier fixture set.

The current review covers 237 of the 600 topics on both builds: 108 PASS and
129 FAIL. The other 363 retain unresolved requirements. These are topic counts,
not additional behavioral test results.

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
