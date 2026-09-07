# Provenance

## Sources

bash-os is assembled from three sources:

- **GNU bash 5.3** (GPL-3.0-or-later), pinned by sha256 in `config/versions.sh`
  and fetched at build time. Its own `examples/loadables/*.c` supply the stock
  builtins a list names but this repo does not carry (`cat`, `chmod`, `head`, …
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
- **Written for bash-os** (MIT): `cut`, the coreutils cut(1) surface — `-b`,
  `-c` (bytes, as GNU's), `-f`, `-d`, `-s`, `-z`, `--complement`,
  `--output-delimiter` (empty means NUL), the long options and their
  prefixes, options after the operands, the range-list grammar and every
  one of its errors, and the whole input as one record when the delimiter
  is the line delimiter (`cut -d $'\n' -f2`) — reading in 64 KB blocks with
  `memchr`, plus the `-a ARRAY` extension that bash's own loadable
  documents. `tests/cut-parity.sh` holds it to byte-identical output and
  status with coreutils 9.7, including unterminated `-z` records. It
  replaces bash's GPL cut loadable in every variant,
  including the pure list: on a 423 KB file the stock one took 8 ms per
  pass, GNU's 2.4 ms, this 1 ms.
- **Written for bash-os** (MIT): `seq`, a clean-room implementation of the GNU
  coreutils seq(1) surface — `[-w] [-s STRING] [-f FORMAT] [FIRST [INCREMENT]]
  LAST`, the precision and equal-width rules, the value one step past LAST
  that rounds to it, the same exit status on a bad number, a zero step or a
  bad format. Integers are counted on a decimal string and written a 64 KB
  block at a time, which is what makes `for i in $(seq N)` fast; floats go
  through the printf format coreutils would use. `tests/seq-parity.sh` holds
  it to byte-identical output and exit status with coreutils 9.7. It replaces
  bash's own GPL seq loadable in every variant, including the pure list.
- **Written for bash-os** (MIT): `zstd` and `zstdcat`, the subset of zstd(1) a
  script uses, over a libzstd found at run time: `libzstd.so.1` is dlopen'ed
  on first use and the stable API resolved with dlsym, so there is no
  link-time dependency and no vendored zstd; without the library the builtin
  says so and fails. Requested by the appliance, which carries the vendor's
  libzstd and compresses its rotated logs with it. zstd(1)'s file semantics:
  the source is kept unless `--rm`, no overwrite without `-f`, the target
  takes the source's mode and mtime. `tests/zstd-check.sh` checks it against
  the host's zstd both ways; `tests/zstd-host.c` runs the buffer paths under
  the sanitizers.

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

## The util-linux family (imported 2026-09-06)

Twenty-five loadables taken from the upstream collection in one batch, renamed
`bashNAME` → `NAME` where prefixed (injector-visible symbols and the command
name in its own strings; internal helpers keep their names), each given an
SPDX line:

`flock setsid ionice blockdev ipcmk ipcctl chattr lsattr mkswap swapon swapoff
wipefs fincore fsfreeze losetup dmsetup getfacl setfacl fstrim prlimit hwclock
renice taskset chrt uclampset`

All plain libc plus Linux headers: no helper tree, no external library, no new
build dependency. `flock` is the one that most wants to be a builtin — `flock -x 9`
locks the descriptor the calling shell opened with `exec 9>lockfile`, which a
forked `flock` cannot do. Fixed on the way in, both found by checking against
the host's util-linux and by `gcc -fanalyzer`:

- `ionice`: a query printed the bare class name for `none` as well as `idle`;
  util-linux prints the priority for every class but `idle` (`none: prio 0`).
- `hwclock`: the adjtime writer skipped its `fclose` when the `fprintf` failed,
  leaking the stream on that path.

Known differences from util-linux, left as they are (these are subsets, not
reimplementations): `lsattr` shows fewer attribute flags, `fincore` and
`prlimit` lay their columns out differently, and `ipcctl` refuses removals by
default policy. `tests/util-linux-smoke.sh` covers what can be exercised
without privilege or destroying anything, and compares `ionice`, `taskset` and
`chrt` against the host's tools.

## The text and formatting tools (imported 2026-09-06)

Nineteen more from the same collection, in one batch, same rename and SPDX
treatment: `expand unexpand split csplit join pr tac column col colrm expr
hexdump tput tinfo strings ed ar uuencode uudecode`. `column.c` registers
three commands (`column`, `col`, `colrm`) and its two companion files exist
only so the build finds a source at each name. Five of them shipped an extra
alias struct for the unprefixed name, which the rename turned into a
duplicate definition; the redundant copy is dropped.

`tests/text-tools-parity.sh` byte-compares 22 invocations against the host's
coreutils and util-linux (all identical), round-trips `uuencode`/`uudecode`
both ways, and checks the host's `ar` can read an archive this `ar` wrote.
`tput` carries a curated capability table (`xterm`, `screen`, `tmux`,
`linux`, `vt100`, `dumb`) with a side-file path for anything else; an
unlisted `TERM` is a clean exit 3, which the test pins.

Fixed on the way in, all found by `gcc -fanalyzer` and all crash-on-
allocation-failure paths of the kind the earlier `diff` fix addressed:
`tac` grew three arrays with unchecked `realloc` and then indexed them,
`csplit` dereferenced an unchecked `calloc`/`malloc` and leaked its pattern
array on five error paths, and `expr` wrote into an unchecked `malloc` in
its substring operator. The remaining analyser reports in this batch are
false positives: a `FILE *` held past a `!= stdin` guard, and `memcpy` from
a buffer `fread` filled.

## What deliberately stays out

`file` is not imported yet, though it compiles and is otherwise ready: its
magic table lists, verbatim, the PEM armour lines that mark RSA, EC, DSA,
OpenSSH and PGP private keys, because those are the strings it recognises.
A pre-publish secret scanner matches them. Importing it needs a decision —
an allowlist for magic tables, or splitting the literals — rather than a
quiet edit that would make the table wrong.

The appliance's four board-coupled managers — `bashnpu`, `bashyolox`,
`bashrtsp`, `detectlog` — depend on NPU/video/detection ABIs and remain in that
project. bash-os is the board-agnostic layer it builds on.

## Local adaptations

Fixes to stock loadables, applied at build time in `build.sh` so the pinned
sources stay as taken:

- `mkdir -p`: only `chmod` the components it actually created, not existing
  parents.
- `fltexpr`: initialise NaN/Inf at compile time (its runtime `_builtin_load`
  hook never fires for a static builtin). Needs `libm`, linked via `LOCAL_LIBS`.

Changes carried in the sources, noted there:

- `ip`: `link set IFNAME address MAC` added (an `IFLA_ADDRESS` attribute on the
  existing `RTM_NEWLINK` request); the collection's version implements only
  `up|down|mtu`.
- `grep`: rewritten around a block reader. The input is read in 96 KB blocks
  and searched a block at a time: a pattern with no regex operator (or `-F`)
  by a memchr scan for its rarest byte and a compare, a regular expression
  by a literal every match must contain, found the same way, with `regexec`
  run only on the lines that carry it, or by one `regexec` over the block
  when no match can hold a newline; line numbers are counted only for `-n`,
  `-B` context is read back out of the block, and output is buffered (bash
  line-buffers stdout, a write per line). The default dialect is GNU's BRE
  compiled as BRE (`\| \+ \? \{ \}` are operators, `+ ? { } |` literal)
  and `-E` is ERE; the previous version compiled every pattern as ERE with
  a paren swap, so `foo\|bar` and `[0-9]\+` never matched and `a+` was a
  quantifier. Reproduced from grep 3.11: `-w` retrying a shorter match at
  the same place and then the next start, `-x`, `-m` with its trailing
  context, the empty-pattern cases, binary files (NULs then separate lines,
  output goes quiet, "binary file matches" on stderr), a printed line that
  is not valid in the locale's encoding, `-z`, `-f -`, patterns split at
  newlines, `-q`'s exit status, and stdin left just after the last match
  for `-m` or at its end when grep stopped early. PCRE2 (`-P`) stays behind
  `BASHGREP_PCRE2` (default 0) so no libpcre2 is needed. Not reproduced:
  `--color` (accepted, no color), and `.` matching a NUL byte under `-a`
  (glibc's `.` never matches NUL). Where the C library has no
  `REG_STARTEND` (musl, so every cross build), a part of a line is matched
  by terminating it in place, and a pattern that has to reach across an
  embedded NUL under `-a` does not match there; measured by forcing that
  path on the host, it is the only difference of the 571.
  `tests/grep-parity.sh` holds it to GNU grep on those 571 command lines in
  a UTF-8 and in the C locale, and `tests/grep-host.c` runs them again
  under ASan+UBSan.
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
- `wc`: a block-reading path for every call without `-m`/`-L` (lines by
  `memchr`, words by a byte state machine that knows the UTF-8 Unicode
  spaces), contributed from the appliance where the decoding loop took
  261 ms on a 423 KB file; now at the speed of the read. Adjusted here: a
  space sequence consumed past the block edge is not rescanned; the
  non-breaking set is U+00A0, U+2007, U+202F, U+2060 and is off under
  `POSIXLY_CORRECT`, as GNU's; in a unibyte locale only the byte 0xA0 joins
  the separators. The `-m`/`-L` path was rewritten to GNU's rules too: an
  invalid byte is a word character but not a character and has no width,
  decoding resumes at the next byte, an incomplete sequence at end of file
  is dropped, only printable characters have width, and CR and FF end a
  line's length. Output columns follow GNU's order (chars before bytes).
  `tests/wc-tail-parity.sh` holds it to byte-identical output with
  coreutils 9.7 in both the C and a UTF-8 locale.
- `tail`: `-n N` on a seekable file reads from the end in 8 KB blocks
  (contributed from the appliance: 3.2 ms to 0.63 ms for `tail -n 1` of an
  89 KB log); the ring buffer remains for pipes. Adjusted here: it never
  looks before the offset the stream was at when called, so a partial read
  followed by `tail` behaves as GNU's does.
- `bashjson`: a duplicate-key check freed its index array and then read the
  return value from it.
- `bashdhcp`: the lease-binding helper treated a null `bind_assoc_variable`
  result as success (the callers ignore the value, so no visible effect).
