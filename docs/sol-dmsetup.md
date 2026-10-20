# dmsetup: independent implementation and fixture review

The predecessor mutation implementation and its follow-up fixes are present in
`eff09ce0a5d29da95ec7b748e6acb2144ea177fc`. This review found and corrected a
kernel ABI mismatch that its original fixture concealed. The production and
fixture corrections are in `155f79cc172dc0376a51eaedf4593c01ba71c163`.

## Corrections

Linux's `ctl_ioctl` normally copies header-only replies through
`offsetof(struct dm_ioctl, data)`, which is 305 bytes on this ABI. It does not
copy all 312 bytes of `sizeof(struct dm_ioctl)`. `remove_all` copies nothing;
an empty name list has no payload; the final status record's alignment padding
is excluded from its reported length. See the
[Linux 6.12 ioctl implementation](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/md/dm-ioctl.c),
particularly `ctl_ioctl`, `list_devices`, `retrieve_status` and `remove_all`.

The inherited validator rejected valid 305-byte replies. Consequently a
successful create/load/resume sequence could report failure and remove the
newly created device during rollback. Successful info, clear, suspend, resume,
rename, remove, silent messages and queries of devices without tables could
also report failure. The validator now normalizes valid header-only replies
to an empty aligned payload. `deps` handles the absence of the selected table.

Names, target-version strings and table parameters are now bounded by their
own records. Truncated and overlapping records fail before their contents are
used. `wipe_table` shares table-record validation with queries, rejects
discontinuous or overflowing geometry, and sends no replacement table when
validation fails. Table-load allocation also checks the complete request
against its size limit before allocation.

All advertised mutation verbs retain their genuine ioctl implementation:
create, load/reload, remove/remove_all, suspend/resume, rename, message, clear
and wipe_table. The root plus `BASHOS_DMSETUP_ALLOW_MUTATE=1` policy remains
ahead of opening the control device. No shared helper changes are required.

## Validation

The original fixture and inherited binary passed 497/497 checks. Against the
corrected fixture and expanded suite, that binary fails 39 of 309 checks
reached; some sections abort after detecting an unexpected request sequence.
The corrected binary passes **631/631** checks, including under ASan/UBSan.
Every pre-existing assertion is retained.

The suite drives the production builtin with `LD_PRELOAD` interception of
device open/close, ioctl and effective uid. An independent Python byte decoder
checks request headers, aligned targets, flags and payloads. Added assertions
cover kernel-sized replies, empty lists/tables, unpadded status output,
record-boundary faults, wipe geometry, the 13-attempt 16 KiB–64 MiB growth cap,
failed rollback, multi-device clear/resume/wipe failures, oversized table
input, and recovery after stdout errors. Existing coverage includes all query
verbs, all mutation verbs, permission failures, input formats, empty PATH,
40 lifecycles in one shell, and descriptor/state cleanup. ASan/UBSan checks
memory access; LeakSanitizer is disabled for the Bash host.

Build only dmsetup:

```sh
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  ./build.sh --include dmsetup --name sol-dmsetup
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  cc -std=gnu11 -O2 -fPIC -shared tests/opus-dmsetup-fixture.c \
  -ldl -o "$EVIDENCE/build/fixture.so"
DMSETUP_FIXTURE_SO="$EVIDENCE/build/fixture.so" \
  python3 tests/opus-dmsetup-ioctl.py out/bash-sol-dmsetup
python3 "$CAMPAIGN/scripts/gated.py" build -- \
  env TMPDIR="$EVIDENCE/build" bash tests/opus-dmsetup-sanitize.sh out/bash-sol-dmsetup
```

Here `CAMPAIGN` is the campaign directory and `EVIDENCE` its task output
directory. The fixture suite never opens a live mapper. The full
`util-linux-smoke.sh` belongs to integrated validation: its other commands
are not companions required by dmsetup. The targeted manifest selects only
dmsetup, with the build's default `_jsmn` helper and no libraries.

## Measurements

`bench/sol-dmsetup.py` preserves the three inherited work units and adds a
600-target table workload. It checks every warm-up and measured pass against
independent expected stdout, status, stderr, ioctl/open/close counts and final
device/table state. Each pass starts a fresh shell and fixture state, with
empty PATH and request logging disabled. Reports include source, binary,
fixture, script and output hashes, tool versions, CPU affinity, every sample
and validation result.

These are **syscall-shim measurements**. They include shell and fixture costs;
they measure no real kernel mapper operation. The inherited reproduction uses
the original fixture, whereas current measurements use the corrected fixture.
They are separate observations, with no speedup ratio. The inherited binary
is not a valid lifecycle reference under the corrected ABI fixture.

Measured on an i7-9850H, Linux 6.12.111, Bash 5.3.15, GCC 14.2, pinned to CPU 2.
Each case has one validated warm-up and nine validated samples. Times below
are whole-process milliseconds, median with minimum–maximum:

| Workload | Fixed work | Corrected fixture and builtin | Inherited reproduction |
|---|---|---:|---:|
| `table-query-64dev` | 1,280 queries, four targets per device | 22.539 (21.049–23.329) | 29.931 (27.823–31.657) |
| `request-lifecycle-100` | 100 create/reload/suspend/resume/rename/remove cycles, 800 ioctls | 5.465 (5.208–6.833) | 7.215 (6.972–8.279) |
| `ls-growth-3000dev` | 20 lists of 3,000 devices, 80 ioctls | 78.065 (71.348–90.422) | 94.025 (90.519–124.598) |
| `table-pack-600` | 20 load/resume/query cycles, 12,000 targets loaded and read, 100 ioctls | 52.004 (48.586–59.751) | not measured |

Raw reports are preserved as `bench/inherited.json` and `bench/current.json`
in the task evidence directory, alongside exact commands and build/test logs.
Current executable SHA-256:
`0391394d8be87f9d0e575cfc7c8503fdd57a4d01c56e698b6a4181f7bf0e67ff`.
Current source SHA-256:
`bc189bd93271755e4a5fc03cda378fa0ac88370d5e8473d45aedf5581980f56e`.
The historical report described a query speedup, not an unresolved slowdown;
no speculative performance change or profiler-based claim was added here.

```sh
python3 "$CAMPAIGN/scripts/gated.py" bench -- \
  python3 bench/sol-dmsetup.py --bash out/bash-sol-dmsetup \
  --fixture "$EVIDENCE/build/fixture.so" \
  --source-commit 155f79cc172dc0376a51eaedf4593c01ba71c163 \
  --samples 9 --warmup 1 --cpu 2 --out "$EVIDENCE/bench/current.json"
```

## Outstanding qualification

No live mapper mutation was performed. A disposable VM with private loop
devices must still qualify kernel target behavior, capabilities, activation,
suspension and flushing, open-device/deferred removal, target messages and
udev behavior, and compare query output with an external dmsetup on the same
devices. No actual-device latency or throughput is claimed.

The predecessor's broader compatibility limits remain: udev cookie
synchronization and node management, EBUSY retry, the `Read Ahead:` info field,
column/report formatting, tree/verbose output and integrity-key masking.
Some corresponding options remain accepted but ignored. This review validates
the stated software/ioctl scope; it does not establish full libdevmapper CLI
or real-device qualification.
