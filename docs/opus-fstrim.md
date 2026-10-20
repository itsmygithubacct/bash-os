# fstrim: mount-table selection, fixtures and measurement

`loadables/fstrim.c` now follows util-linux 2.41 `fstrim(8)` for every
table mode. The earlier `-I/--listed-in` read field 2 of each line and
reported (and without `-n` would have trimmed) any path that merely
`stat()`ed, including ordinary files. `-A` read `/proc/self/mounts`
instead of `/etc/fstab`.

## Behaviour

* `-a` reads `/proc/self/mountinfo`, `-A` reads `/etc/fstab`, and `-I LIST`
  reads the first regular, non-empty file of a colon-separated list. Missing
  and non-regular files are skipped. A list with only empty files exits 255,
  and one with no usable file exits 32. The three options are mutually
  exclusive, and a repeated `-I` keeps the last value.
* The format is guessed from the first entry line. Fields are
  blank-separated, and `\ooo` octal escapes are decoded (`\040` space,
  `\011` tab, `\134` backslash). An fstab line needs source, target and type.
  A mountinfo line needs the ` - ` separator, type, source and
  superblock options. Malformed lines are skipped.
* Duplicate targets (compared like libmount `streq_paths`, ignoring repeated
  and trailing slashes) keep the **last** entry.
* Each entry must then pass every check below:
  * It is not a pseudo, network, swap or autofs type.
  * Its options do not include `ro` or `X-fstrim.notrim`.
  * It matches `-t` (libmount `match_fstype`: case-insensitive, global or
    per-item `no` negation).
  * `statfs` succeeds and is not autofs.
  * `access(W_OK)` does not fail with EROFS or EACCES.
  * The source is an absolute path. Tags are resolved through
    `/dev/disk/by-*` only for `-A`.
  * The target is **really a mountpoint now**. This is libmount's
    `mnt_get_mountpoint`: walk up while `st_dev` is unchanged, then compare
    paths.
  * The target is a directory.
  * sysfs does not report zero `discard_granularity` or `ro` for the
    device. Partitions read their disk's queue, and unknown devices count as
    capable.
* Duplicate sources then keep the **first** entry, and survivors are trimmed
  in reverse table order. `-A` adds the root device (`root=` from
  `/proc/cmdline`, otherwise the device of `/`) when fstab has no `/` entry.
* Exit codes: 0, 32 (every trim failed), 64 (some failed), 1 (usage).
  ENOTTY, EOPNOTSUPP and EBADF are "not supported" warnings, and
  `--quiet-unsupported` silences them.
* Single-mountpoint mode accepts any directory, as util-linux does.
* `-o/-l/-m` use util-linux `parse_size`: base-0 integers, fractions with a
  suffix, `K`…`Y` with optional `iB` (1024) or `B` (1000), and ERANGE
  reported. `-l 0` is passed through instead of becoming "everything".
* Option parsing follows `getopt_long`: permutation, bundling, `--opt=value`,
  unique abbreviations and the same diagnostics. `-v` prints
  `size_to_human_string` sizes. Write errors on stdout report
  `write error: …` and exit 1.

The mount-table, fstab, cmdline, sysfs and `/dev/disk` paths are
compile-time macros. The tests use them to compile the same source against
fixtures.

## Tests

| file | what it runs |
|---|---|
| `tests/opus-fstrim-oracle.sh BIN [PRELOAD]` | util-linux and the builtin in one private user+mount namespace over fresh tmpfs mounts. 214 dry-run invocations cover lists, duplicates, escapes, filters, types, mountinfo, colon lists, usage, every libmount pseudo/net type name, and 40 size strings for each of `-o/-l/-m`. 78 non-dry invocations go through `opus-fstrim-preload.c`, an `ioctl` interposer that answers FITRIM itself and logs the range. stdout, stderr, status and every FITRIM request (start, len, minlen) must be identical. The builtin side runs twice in one shell with `PATH=` and an fd count check. |
| `tests/opus-fstrim-check.py` | the production source compiled by `opus-fstrim-shim.c` against a closed node table (stat/access/statfs/realpath/open/close/ioctl) plus a private sysfs, `/dev/disk`, mountinfo, fstab and cmdline. It covers 27 cases: the paths a namespace cannot reach (EACCES, autofs magic, statfs failure, sysfs partition/whole-disk/ro/missing-attribute discard, `class/block` lookup, `-a`/`-A` defaults, tag resolution, root guessing), FITRIM failures and exit 32/64, realpath/open failure, write errors and fd balance. It runs a second time under ASan/UBSan. |
| `tests/opus-fstrim-build.sh` | compiles the shim, its sanitizer build and the preload. Run it only through the build gate. |

FITRIM never reaches the kernel in any test. The oracle's targets are tmpfs,
which has no FITRIM, and the namespace has no CAP_SYS_ADMIN over the host.

## Measurement

The historical case `fstrim -n -I left` (`bench/loadables.py`, self-timed,
60.86 ms in the old dataset) measured invalid output. Its fixture lines
(`000000 left`) have no filesystem type. util-linux therefore parses an
empty table and exits 255, and so does the builtin now. Re-running the
unchanged harness records `status: error, returncode 255` and no timing.
The old number is kept as history only.

`bench/opus-fstrim.py` is a matched comparison. Each pass of each batch is
checked against util-linux's own stdout, stderr and status on that fixture.
CPU 5 was pinned, with 7 runs of 20 passes and a validated warm-up. Results
from 2026-10-19 (`fstrim.c` sha256 `81a0da15…`, binary `f2d2d392…`):

| workload | builtin per call | util-linux per call | ratio |
|---|---|---|---|
| historical-left (10,000 rejected lines, status 255) | 0.474 ms | 3.559 ms | 0.133 |
| mounted-list (10,000 entries, 64 mounted, 64 lines out) | 136 ms | 19,030 ms | 0.0072 |

The util-linux figure for `mounted-list` is dominated by libmount table
work that grows faster than linearly with table size. The builtin
deduplicates with a hash set. The host load average was about 9 during
these runs, so treat the spread in the raw samples as part of the result.

## Limits

* `/dev/root` and udev-encoded label characters are not resolved, and
  bind mounts of the same device are not mountpoints (as in libmount).
* Real FITRIM on a discard-capable device has not been run. Hardware
  qualification would need a privileged host with a scratch device.
