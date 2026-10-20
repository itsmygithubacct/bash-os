# rsync: destination rule, local copies, atomic writes

This covers the push paths of `loadables/rsync.c`: local copies and
`[HOST]:DEST` over an rsh command. Pull, `--native` (proto-27) and daemon
transfers were not changed.

## What changed

- **DEST rule.** When DEST does not exist and there is one non-directory
  source, the builtin used to create DEST as a directory. Stock rsync
  (`get_local_name()`) writes a file there. The builtin now applies the
  same rule. DEST is a directory if it already is one (a symlink to a
  directory counts), if it ends in `/`, or if the sources add up to more
  than one entry: several surviving sources, or a recursed directory.
  Otherwise one file is written at DEST.
  - A missing directory DEST is created one level deep. A missing parent
    exits 11, as stock rsync does.
  - A file DEST with a missing parent exits 3.
  - An existing non-directory DEST that must be a directory exits 3, with
    stock rsync's message.
- **Local copies.** A plain `rsync SRC DEST` with no host used to exec the
  default rsh (`ssh "mkdir -p DEST"`), so it always failed. It now copies
  inside the shell with syscalls, with no external programs and no PATH
  lookups. An explicit `-e` still sends a plain DEST through the rsh
  transport with an empty host, as before; `tests/final-smoke.py` uses
  that form to reach `--delta`.
- **Atomic writes.** Both transports now write each file to
  `DIR/.NAME.XXXXXX`, set its metadata, then rename it over the target.
  Before, the rsh path ran `cat > DEST`, which truncated the old file in
  place. A write that fails part-way (tested with RLIMIT_FSIZE) now:
  removes the temporary, leaves the old file intact, exits 11 and stops
  the transfer, like the stock receiver.
- **Flags.** `-r`, `-l`, `-p`, `-t` (and `-D`, which is accepted and
  ignored) are now accepted on their own, and `-a` means `-rlptog`.
  - Without `-r`, directories are skipped with `skipping directory NAME`.
  - Without `-l`, symlinks are skipped with `skipping non-regular file "NAME"`.
  - Without `-p`, an existing file keeps its mode and a new file gets the
    source mode under the umask.
  - Directory mode and mtime are applied after the directory's contents.
    For `SRC/` copies, DEST's own metadata waits until every source is
    done.
  - With `-p`, a file whose size and mtime match is not resent, but its
    mode is still fixed.
- **Exit status** on the push paths follows rsync:
  - 23: some entries failed (missing or unreadable source, unwritable
    directory) and the rest were sent.
  - 3: DEST cannot be used.
  - 11: DEST cannot be created, or a write failed.
  - 2: usage errors, as for every builtin (stock rsync returns 1).
- **rsh probes.** Remote stat probes no longer follow symlinks, and they
  read the mode as well. Walk directories are made with `mkdir`, not
  `mkdir -p`; a non-directory in the way is replaced.

## Spawn cost on the rsh transport

For a single file to an existing DEST, each pass used to spawn four remote
shells: `mkdir -p`, `stat`, `cat >`, then chmod/touch/chown. It now spawns
two. The first is one DEST probe, which also answers the file's own size,
mtime and mode probe. The second is one write script: noclobber temporary,
`cat`, chown, chmod, touch, `mv`, with no subshell. A missing directory
DEST adds a `mkdir` spawn. With `-a` or `-p`/`-t`, each directory in a
recursive copy costs one more spawn (its metadata) than before.

## Validation

`tests/opus-rsync-check.py BASH [--load SO] [--preload LIBASAN]` builds the
same private fixture twice for each scenario. One copy runs stock rsync,
the other runs the builtin, and after every step it compares:

- the exit status
- the `skipping ...` lines
- the whole resulting tree: type, mode, size, SHA-256, link target, and
  whether each mtime is a preserved fixture time or a fresh one

The fixture times include nanoseconds, compared exactly on the local path
and to the second over the rsh transport. A leftover temporary file would
show up as an extra tree entry.

All builtin calls for a transport run in one bash-os shell with an empty
PATH. The shell's open descriptors are compared before and after.

There are 40 scenarios, all run on both transports except the empty-DEST
case, which is local only. They cover:

- single files to new, existing, slash-terminated, missing-parent,
  under-a-file and symlink destinations
- several sources, including missing ones
- directories with and without a trailing slash, `..` and `.` sources,
  symlinked destination directories, and a file replaced by a directory
- non-recursive copies and recursion without `-l`
- `-rt`, `-rp`, read-only source directories, fixing perms when the
  content is unchanged, and keeping an existing mode without `-p`
- dry runs, `--delete`, and repeated calls with source edits in between
- a read-only destination, an unreadable source and an empty DEST
- an interrupted copy over an existing file and into a new directory, with
  RLIMIT_FSIZE set and SIGXFSZ ignored for both implementations

Results, against stock rsync 3.5.0 (protocol 32):

| binary | checks | failures |
|---|---|---|
| baseline (`2317322`) | 143 | 116 |
| final, static builtin | 143 | 0 |
| final, ASan+UBSan object (`tests/opus-rsync-so.sh OUT asan`) | 143 | 0 |

`--delta`, `-z`, `-n` and the server sub-modes were also run through
`-e "$BIN -c"`. The delta case reported `2045 delta / 153600 file bytes`.
Usage errors, an empty PATH, closed stdout and repeated calls in one shell
were checked too, with stable descriptors.

## Measurements

`bench/opus-rsync.py` resets DEST before every pass and runs the same
arguments through the builtin and through stock rsync (absolute path),
from one bash-os shell with an empty PATH, pinned to one CPU.

- **Validation:** every pass of both implementations is first driven from
  a persistent shell, and the full DEST tree is compared after each one.
- **Timed batches:** each pass's status is checked, each reset asserts the
  previous pass left the expected entry type, and the final tree is
  compared again.
- **Runs:** one warm-up, then 7 samples of 11 passes each.

Final static build (`out/bash-opus-rsync`, rsync+rm+mkdir, source sha256
`b0097864…`), CPU 11, load average about 3. Times are the median batch
in milliseconds:

| case | bash-os ms | stock ms | ratio |
|---|---|---|---|
| rsync-rsh-shim (historical: `text :rdest/`) | 67.8 | 568.6 | 0.119 |
| rsync-rsh-file-to-dir (`text :rdest`) | 58.7 | 553.2 | 0.106 |
| rsync-rsh-file-to-file (`text :rout`, new) | 63.0 | 553.1 | 0.114 |
| rsync-local-file-to-file (`text lout`, new) | 4.9 | 535.8 | 0.009 |
| rsync-local-file-to-dir (`text ldest`) | 6.9 | 536.7 | 0.013 |
| rsync-local-big-file-to-file (16 MiB) | 114.2 | 775.5 | 0.147 |
| rsync-local-tree (200 × 2 KiB in 8 dirs, `tree/ ltree`) | 85.3 | 633.8 | 0.135 |

The unchanged `bench/loadables.py --only rsync-rsh-shim` run on the same
binary gave 77.0 ms for bash-os and 623.5 ms for stock, at 12 calibrated
passes.

### Before and after

These runs loaded each rsync object with `enable -f` into the same binary,
one after another. Host load was 8–30, so compare them only with each
other. Times are the median of 11-pass batches in milliseconds:

| case | baseline | new, before optimizing | optimized |
|---|---|---|---|
| rsh-shim | 165.9 | 170.1 | 138.6 |
| rsh-file-to-dir | 167.9 | 164.0 | 143.8 |
| rsh-file-to-file | wrong output (directory) | 181.0 | 158.2 |
| local cases | wrong output (exec ssh) | — | — |
| local-big-file-to-file | wrong output | 250.6 | 212.5 |

The optimizations were made only after the parity suite passed. They are
the shared DEST/file probe, removing the noclobber subshell, and
`copy_file_range` with a read/write fallback.

## Remaining differences

- Over the rsh transport, mtimes are kept to the second (`touch -d`
  ISO); the local path keeps nanoseconds.
- `-v` output is the builtin's own (one path per line on stderr), not
  stock rsync's file list on stdout.
- Error messages follow stock rsync's wording for the cases above, but
  are not byte-identical.
- Devices, FIFOs and sockets are always skipped.
- Hard links (`-H`), ACLs and xattrs are not supported (as before).
