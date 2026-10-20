# dmsetup: mapper mutation verbs, fixture coverage and measurements

`loadables/dmsetup.c` speaks the kernel DM ioctl ABI on `/dev/mapper/control`
directly. There is no libdevmapper. This note covers what the builtin does,
how it is tested without touching a real mapper, what was measured, and what
still needs a real device to qualify.

## Verbs

| verb | requests sent (in order) | notes |
|---|---|---|
| `create NAME [-u UUID] [-r] [-n] [-j MAJ -m MIN] [TABLE]` | `DM_DEV_CREATE`, then if the table has targets `DM_TABLE_LOAD` and `DM_DEV_SUSPEND` (resume) | Like libdevmapper, a failed load or resume is followed by `DM_DEV_REMOVE`. `-j/-m` set `DM_PERSISTENT_DEV_FLAG`. `-r` sets `DM_READONLY_FLAG` on the load. |
| `load`/`reload DEV [-r] [TABLE]` | `DM_TABLE_LOAD` | Loads the inactive table. |
| `remove [-f] [--deferred] DEV...` | `DM_DEV_REMOVE` for each device | `--deferred` sets `DM_DEFERRED_REMOVE`. `-f` first replaces the table with an `error` target, as libdevmapper does. |
| `remove_all [-f]` | `DM_REMOVE_ALL` | `-f` first wipes every listed device. |
| `suspend [--noflush] [--nolockfs] DEV...` | `DM_DEV_SUSPEND` with `DM_SUSPEND_FLAG` | The two options add `DM_NOFLUSH_FLAG` and `DM_SKIP_LOCKFS_FLAG`. |
| `resume DEV...` | `DM_DEV_SUSPEND` without flags | Swaps in the inactive table. |
| `rename DEV NEW` / `rename DEV --setuuid UUID` | `DM_DEV_RENAME` with the new name, or the uuid plus `DM_UUID_FLAG`, at `data_start` | Empty, over-long and `/`-containing names are refused before any ioctl. |
| `message DEV SECTOR MSG...` | `DM_TARGET_MSG` (`struct dm_target_msg`, words joined by spaces) | A `DM_DATA_OUT_FLAG` reply is printed, with a newline added if it lacks one. |
| `clear DEV...` | `DM_TABLE_CLEAR` | Drops the inactive table. |
| `wipe_table DEV...` | `DM_TABLE_STATUS`, `DM_TABLE_LOAD` (one `error` target covering the device's size), resume, and `DM_TABLE_CLEAR` if the resume fails | Follows libdevmapper's `_error_device`. It is not the same as `clear`. |
| `ls [--target T]`, `info`, `table`, `status`, `deps [--inactive]`, `targets`, `version` | `DM_LIST_DEVICES`, `DM_DEV_STATUS`, `DM_TABLE_STATUS` (with or without `DM_STATUS_TABLE_FLAG`), `DM_TABLE_DEPS`, `DM_LIST_VERSIONS`, `DM_VERSION` | With no device argument, these run for every device and prefix each line with `NAME: `, as dmsetup does. |

All of the mutating verbs are listed above. For them, the explicit mutation
policy has not changed: they fail unless the effective uid is 0 and
`BASHOS_DMSETUP_ALLOW_MUTATE=1`. This check runs before
`/dev/mapper/control` is opened.

### Request layout and response handling

- Every request is a `struct dm_ioctl` header for version 4.x, with
  `data_start = sizeof(struct dm_ioctl)`. Names of 128 bytes or more and uuids
  of 129 bytes or more are refused. The old builtin truncated them silently,
  so a request could address a different device.
- Table text comes from `--table`, from a table file argument, or from stdin
  when stdin is not a terminal. If the argument is not an existing file, it
  is taken as table text, which is what the old builtin did. Tables can have
  several lines; blank lines and `#` comment lines are skipped. Errors use
  libdevmapper's `Invalid format on line N of table SRC` wording. Malformed
  text never reaches the kernel: non-numeric, negative or overflowing
  numbers, a missing type, a type of 16 bytes or more, or a NUL in the file.
- Each `dm_target_spec` is padded to 8 bytes. Its `next` field is the
  distance to the following spec, which is the layout `populate_table`
  expects.
- Commands that return data (`names`, `table`/`status`, `deps`, `versions`,
  `message`) start with a 16 KiB buffer. While the kernel sets
  `DM_BUFFER_FULL_FLAG`, the buffer doubles, up to 64 MiB, and the payload is
  rebuilt each time. The old builtin used a fixed 64 KiB buffer and ignored
  the flag.
- Before anything in a response is used, it is bounds-checked against the
  `data_size` it reports, clamped to what was allocated. This covers
  `data_start`/`data_size`, `next` chains, the NUL termination of names,
  params and replies, and the dependency count. A malformed response
  produces `malformed ... response` and a failure status.
- The old `ls`/`info` read `target_count` after `DM_LIST_DEVICES`. The
  kernel's `list_devices` never sets that field, so against the fixture
  model they reported `No devices found`. The new code walks the name list
  until `next == 0`. It also accepts the 5.13+ records that carry
  `event_nr`, flags and uuid after the name.
- Error output follows libdevmapper: `device-mapper: <cmd> ioctl on <name>
  <uuid> failed: <strerror>`. A missing device on a query prints `Device does
  not exist.`. A failed command prints a single `Command failed.` at the end.
  Multi-device verbs keep going after a failure and return status 1.
- `table` hides the hex key of `crypt` targets as zeros unless `--showkeys`
  is given. Keyring references (`:size:type:desc`) are shown as they are.
- `info` adds `Tables present:` and `(READ-ONLY)`/`(DEFERRED REMOVE)` state
  suffixes. It prints `Number of targets` only when there is a live table,
  and `UUID` only when the device has one.
- The control descriptor is opened `O_CLOEXEC` and closed on every path.
  Stdout write errors are reported through `sh_chkwrite`.

## Fixture testing

`tests/opus-dmsetup-fixture.c` is an `LD_PRELOAD` object. It interposes
`open`, `close`, `ioctl` and `geteuid`, so the unchanged production builtin
talks to an in-memory mapper model instead of the kernel. Here is what the
model does:

- It validates requests the way `drivers/md/dm-ioctl.c` does. That covers
  the version, `data_size`/`data_start`, NUL-terminated name and uuid, and
  rejecting a request that sets both name and uuid. For loads it checks the
  spec bounds and params termination, that targets adjoin, non-zero lengths,
  known target types and linear parameters. It is stricter than an x86
  kernel in one place: specs must be 8-aligned.
- It answers with responses shaped like the kernel's, including
  `DM_BUFFER_FULL_FLAG` and the 5.13+ name-list records.
- It logs every request byte for byte.
- It can inject errnos per command and device (`DMSFIX_FAIL`), a failing
  open (`DMSFIX_OPEN_ERRNO`), malformed responses (`DMSFIX_MALFORM`) and the
  effective uid (`DMSFIX_EUID`).

`tests/opus-dmsetup-ioctl.py BASH` decodes the logged requests with its own
`struct` layout. It does not use the C headers, so it is an independent
oracle. It checks:

- Policy: every mutating verb is refused for non-root, for root without the
  opt-in, and for an opt-in value other than `1`, with no open of the
  control node.
- Create sequences, including byte-exact table payloads, flags, persistent
  devices, `--notable`, file, stdin, terminal-stdin and inline tables, and
  reverting after a failed load or resume.
- Malformed tables: ten kinds, each rejected before any ioctl.
- Load, reload, clear, and querying the inactive table.
- A 600-target payload and the status buffer growing to fit it.
- Suspend and resume flags, and multi-device errors (EPERM, EBUSY, ENXIO).
- Deferred and forced remove, `remove_all` with and without `-f`, and
  `wipe_table`, including a failed resume followed by a clear.
- Rename and `--setuuid`, by name or by `-u`.
- Message payloads, and a 40000-byte reply growing the buffer 16→32→64 KiB.
- Query output: `ls`, `info`, `table`, `status`, `deps`, `targets`,
  `--target`, `--inactive`, crypt key hiding, `version`, and an empty mapper.
- 3000 devices growing the `names` buffer 16→128 KiB.
- Seven kinds of malformed response.
- Permission failures: EACCES on open, and EPERM from every ioctl.
- One shell running 40 full lifecycles with `PATH` empty, with no leaked
  descriptor (both `/proc/$$/fd` and the fixture's open/close counts are
  checked).
- `/dev/full` output errors, and usage and option errors.

`tests/opus-dmsetup-sanitize.sh BASH` rebuilds `dmsetup.c` with
ASan/UBSan, loads it with `enable -f` over the builtin, and runs the same
suite. The script compiles, so run it under the campaign build gate.

Run against the pre-change builtin (`5a91c6e`), the fixture suite fails 70
of the 344 checks it reaches. A pre-change `create` with a multi-line table
cannot produce the expected request sequence, so a few sections abort, and
each counts as one failure.

The expanded suite passes 497 checks normally and under ASan/UBSan. It also
covers a control open that fails once and would succeed on retry: named/UUID
`info` and target-filtered `ls` now report the original error without reopening
the device or leaking a descriptor. Fixed-header string and alignment checks
are validated against the current source, rather than the older saved binary.

## Historical measurements (syscall-shim)

The numbers below measured commit `69736201678c3abfe3ccf88755d69007b63c1319`.
They predate the response-validation and control-open corrections and do not
measure the corrected implementation. A fresh gated run is required before
claiming current performance.

`bench/opus-dmsetup.py` times whole `bash -c` processes. Each process runs a
fixed loop of dmsetup calls against the fixture. Every pass, warm-up
included, is checked against stdout, exit status, stderr, the fixture's
ioctl count and its descriptor balance, all computed independently in the
harness. These are **syscall-shim timings**: no kernel device-mapper is
involved, and no ratio against an external dmsetup is claimed. Only
`table-query-64dev` is valid on the pre-change builtin, so it is the only
workload with a pre/post pairing on the same host and fixture. The
pre-change `ls` cannot list devices (see the `target_count` item above), and
its `create` rejects multi-line tables.

One gated run (2026-10-19): x86_64, Linux 6.12, pinned to CPU 2, one
warm-up and nine samples per binary. The medians below are whole-process
wall times.

| workload | work unit | new | pre-change |
|---|---|---|---|
| `table-query-64dev` | 1280 `dmsetup table NAME` calls (64 devices × 4 targets) | 18.1 ms (15.9–20.1) | 26.8 ms (26.0–29.9) |
| `request-lifecycle-100` | 100 × create(16-target table)/reload/suspend/resume/rename/remove, 800 ioctls | 9.9 ms (9.2–13.8) | not valid on the old builtin |
| `ls-growth-3000dev` | 20 `dmsetup ls` over 3000 devices, 4 `names` requests each | 56.9 ms (53.2–58.1) | not valid on the old builtin |

On the paired query workload, the new builtin takes 0.67× the time of the
old one. The difference is consistent with the starting buffer: the old
builtin allocated and zeroed 64 KiB for every query, and the new one
starts at 16 KiB and grows only when the kernel asks. No profiler was run.
There was no earlier measured case to reproduce, and the absolute costs are
small: about 14 µs per `table` call and 17 µs per mutating call, both
including fixture overhead. So no further optimization was attempted.

## Real-device qualification still outstanding

There is no fixture substitute for any of the following:

- Running each mutating verb against a real kernel's `/dev/mapper/control`
  as root, for example on a disposable VM with loop devices: create, load,
  resume, suspend (with `--noflush`/`--nolockfs`), rename and
  `--setuuid`, message (thin-pool or similar), wipe_table, remove
  (`--deferred` on an open device) and remove_all.
- Byte-comparing `table`, `status`, `info` and `deps` against the host's
  dmsetup on the same devices.
- udev cookies, `/dev/mapper` node creation and `--retry` are not
  implemented. The builtin relies on udev or devtmpfs creating the nodes.
- `info` has no `Read Ahead:` line, because that needs `BLKRAGET` on the
  device node.
- The report options `-c`/`-C`/`-o`/`--columns` are accepted for
  compatibility but ignored. `ls --tree` and `-v` are ignored too.
- Only `crypt` keys are masked. Keys inside `integrity` optional arguments
  are not.
