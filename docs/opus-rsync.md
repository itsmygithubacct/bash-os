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

The scenarios run on both transports except the empty-DEST case, which is
local only. They cover:

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

The oracle compares exit status and destination contents with stock rsync.
It also checks descriptor counts across repeated calls in one shell.

## Remaining differences

- Over the rsh transport, mtimes are kept to the second (`touch -d`
  ISO); the local path keeps nanoseconds.
- `-v` output is the builtin's own (one path per line on stderr), not
  stock rsync's file list on stdout.
- Error messages follow stock rsync's wording for the cases above, but
  are not byte-identical.
- Devices, FIFOs and sockets are always skipped.
- Hard links (`-H`), ACLs and xattrs are not supported (as before).

For multiple source directories merged into one destination, `--delete`
checks the union of source-to-destination mappings, including nested paths.
The parity suite exercises overlapping directory contents through both
transports; `tests/astra-rsync-delete.py BINARY` is a focused local regression.
