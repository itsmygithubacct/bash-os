# Provenance

## Sources

bash-os is assembled from three sources:

- **GNU bash 5.3** (GPL-3.0-or-later), pinned by sha256 in `config/versions.sh`
  and fetched at build time. Its own `examples/loadables/*.c` supply the stock
  builtins a list names but this repo does not carry (`cat`, `chmod`, `cut`, …
  — the whole of `bash-loadables-pure.list`).
- **An upstream bash-os loadables collection** (MIT, "bash_linux contributors").
  The busybox-replacement loadables — `ls cp mv find sed sort grep ip ps pax`
  and the rest — and the injection technique originate there. This repo carries
  a curated subset, with the injector-visible symbols renamed from `bashNAME` to
  the real command name so an empty-`PATH` script resolves them.
- **Loadables written for the `lichee-nano-bashos` appliance** (MIT), generic
  enough to belong here: `httpd` (an HTTP server primitive), `rngseed` (credits
  a saved kernel random seed), `rtspcat` (an RTSP/RTP H.264 client),
  `reboot`/`halt`/`poweroff`/`chown`/`chgrp`.
- **Written for bash-os** (MIT): `stat`, a clean-room implementation of the
  GNU coreutils stat(1) surface (format directives, default and terse layouts,
  `--printf`, `-L`, birth time via statx) plus a small `-A NAME` array load.
  `tests/stat-parity.sh` holds it to byte-identical output with coreutils 9.7.
  It replaces bash's own GPL stat loadable in every variant, including the
  pure list.

## Licences, file by file

| Files | Licence |
|---|---|
| everything in `loadables/` | MIT (`LICENSE`) |
| `loadables/_jsmn/` | MIT, zserge/jsmn, its own `LICENSE.txt` |
| `tests/*.c`, `build.sh`, `config/` | MIT |

Every source carries an `SPDX-License-Identifier` line or an MIT statement in
its header; `tests/licence-check.sh` fails the suite if a file lacks one or is
not MIT. Several MIT files note explicitly
that the *combined binary* is GPL-3+ — that is bash's licence, not theirs.

## What deliberately stays out

The appliance's four board-coupled managers — `bashnpu`, `bashyolox`,
`bashrtsp`, `detectlog` — depend on NPU/video/detection ABIs and remain in that
project. bash-os is the board-agnostic layer it builds on.

## Local adaptations

Fixes to stock loadables, applied at build time in `build.sh` so the pinned
sources stay as taken:

- `cut`: the output buffer was sized with `strlen()` *after* `strsep` had
  overwritten the field delimiters with NULs, so a multi-field range overflowed
  the heap. Sized from the line length taken before the split.
- `mkdir -p`: only `chmod` the components it actually created, not existing
  parents.
- `fltexpr`: initialise NaN/Inf at compile time (its runtime `_builtin_load`
  hook never fires for a static builtin). Needs `libm`, linked via `LOCAL_LIBS`.

Changes carried in the sources, noted there:

- `ip`: `link set IFNAME address MAC` added (an `IFLA_ADDRESS` attribute on the
  existing `RTM_NEWLINK` request); the collection's version implements only
  `up|down|mtu`.
- `grep`: built POSIX-regex only; PCRE2 (`-P`) is behind `BASHGREP_PCRE2`
  (default 0) so no libpcre2 is needed, and `-P` errors cleanly at run time.
- `pax`: the collection's `bashpax.c`, renamed; plain libc ustar list, create,
  extract and copy with PAX and GNU long-name headers read and `..` rejected.
  Fixed here: bodies were skipped with `fseek`, which fails on a pipe, so
  `cat x.tar | pax -r` lost every member after the first; a member is now
  written to a fresh file rather than through whatever sits at its name (a
  pre-existing symlink was followed); a PAX `size` beyond `long` no longer
  wraps into a backwards seek; and a full-length 257-byte ustar name is no
  longer truncated. Writing: a size above 8 GiB or a uid/gid above 2097151
  used to be silently truncated in the ustar field; it now goes into a PAX
  extended header (the reader already honoured them) and the field is
  clamped, never garbage.
- `cp`: a device, fifo or socket destination is written into, as coreutils
  does (`cp file /dev/null`); it used to be refused. Copying onto a symlink
  that points back at the source truncated the source before the same-file
  check: it now opens without truncating, compares the open descriptors'
  inodes, then truncates (contributed with `tests/regressions.py`).
- `diff`: the line-table growth is checked; out of memory is an error, not a
  crash.
- `bashjson`: a duplicate-key check freed its index array and then read the
  return value from it.
- `bashdhcp`: the lease-binding helper treated a null `bind_assoc_variable`
  result as success (the callers ignore the value, so no visible effect).
