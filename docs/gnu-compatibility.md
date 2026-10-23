# GNU command compatibility

The `core` profile and its descendants include `base64`, `sha256sum`, `gzip`,
and `tar`. They are native builtins, including in static and scratch Docker
builds. No host utility is invoked. `clear` and `bashclear` are described in
[clearing the terminal](clear.md).

| Command | Supported interface |
|---|---|
| `base64` | Encode or decode a file or stdin; `-d`, `-i`, `-w`, their long names, clustered short options, and `--`. Encoding wraps at 76 columns by default; `-w0` disables wrapping and the final newline. Decoding accepts concatenated padded groups and GNU-style incomplete final groups, reports invalid input, and preserves binary bytes. |
| `sha256sum` | Files or stdin; text/binary markers, `--tag`, `-z`, escaped filenames, and `-c` verification of GNU and BSD checksum files. Check mode supports `--quiet`, `--status`, `--warn`, `--strict`, and `--ignore-missing`. |
| `gzip` | File compression/decompression and stdin/stdout filters; `-c`, `-d`, `-k`, `-f`, `-t`, `-n`, `-q`, `-1` through `-9`, and `-S`. Checks CRCs and truncation and decodes concatenated members. File output is published only after a complete stream; failed decompression retains its input. |
| `tar` | Create, list, and extract ustar/PAX archives; `-c`, `-t`, `-x`, `-f`, `-C`, `-z`, `-v`, `-O`, `-p`, `--strip-components`, and `--no-recursion`. Supports traditional `tar cf archive files` syntax. `-C` affects member paths and restores the caller's working directory on success and failure. |

`bashbase64` keeps its original unwrapped encoding default and extended
decoding rules. Use `base64` for the GNU interface.

`cp -n` and `--no-clobber` skip existing destination entries with successful
status and no output. Copying regular data to a dangling destination symlink
still fails, as GNU cp does. `-f` does not cancel `-n`;
the last `-i` or `-n` wins. Recursive directory copies still merge directories.
Exclusive creation also protects a destination created after the initial check.
Nonrecursive `cp` follows source symlinks by default; use `-P` to copy the
symlink itself. Recursive and archive copies preserve symlinks unless a
dereference option is selected. `cp -f` writes through an openable destination
and removes it only after a failed write-open; same-file destinations are
rejected before truncation. `mv` reports a declined interactive overwrite as a
failure and checks the source even when `-n` would skip the destination.
`find` reports missing starting paths and directory cycles as failures while
continuing later roots, and stops traversal at `-maxdepth`.

`env` keeps the last value of repeated assignments and searches the child
environment's `PATH` when launching an external command. `od` treats multiple
input files as one stream: words, lines, offsets, duplicate suppression and
GNU `-S` strings can cross file boundaries, and `-j`/`-N` apply to the combined
input. Its custom `-s` string mode retains its separate per-file contract.
`df` selects the mount containing each operand and reports the original file
operand separately from the mount target. `du -L` counts a followed inode once
unless `-l` requests duplicate counting.

`touch -d` and `--date` accept `@SECONDS` with an optional sign and decimal
fraction, including dates before the epoch. Fractions are represented as integer
nanoseconds. `cat --` ends option parsing; `cat` also supports the common GNU
numbering, blank-line squeezing, and nonprinting-byte display options.

The stock loadables also carry focused compatibility corrections:

| Commands | Corrected behavior |
|---|---|
| `basename`, `dirname` | Empty operands, argument errors, and multiple `dirname` operands with optional NUL termination. |
| `mkdir`, `mkfifo`, `chmod` | Explicit creation modes, umask handling, conditional `X`, symbolic permission copies and special bits. `chmod` supports recursive, force and verbose operation; recursive traversal skips descendant symlinks. |
| `printenv` | Multiple exported names, continued processing after a missing name, NUL termination, and GNU option ordering. |
| `realpath` | A missing final component, final dangling links, and lexical `-s` normalization. `-e` selects existing paths. |
| `rmdir`, `unlink` | Parent removal with `rmdir -p`; `unlink` validates exactly one operand before removing anything and accepts `--`. |
| `id`, `whoami`, `logname`, `uname` | Group formatting and deduplication, named users, option aliases, operand validation and GNU error statuses. Identity tests use a synthetic account database. |
| `getconf`, `pathchk`, `finfo` | Undefined configuration values and listing format, pathname limits, and sticky permission bits. |
| `sleep`, `tty`, `mktemp`, `rm`, `tee`, `touch`, `tail` | Multiple sleep intervals and corrected argument-error handling. |
| `stat` | Unknown format directives produce `?`; an unavailable SELinux context prints `?` and reports failure. |
| `strftime`, `strptime` | Negative epochs, common date/time formats, independent parsing attempts, and numeric UTC offsets. |

The custom `date`, `free`, `wc`, `tr`, `truncate`, `uniq`, `comm`, `fold`,
and `paste` implementations also use GNU failure statuses for invalid arguments.
`rev --` ends option parsing. `cmp -l` aligns byte offsets and octal values with
the GNU output format, including comparisons involving standard input.
`xargs -L` counts nonblank logical lines while splitting their words into
arguments. Its quoting, trailing-blank continuation, `-n`/`-L`/`-I` precedence,
size limits and child-status diagnostics have focused GNU comparisons.
The `lsattr` interface matches e2fsprogs' short flag columns, symlink errors,
dot entries and recursive headings on ordinary private files. Attribute-setting
operations and enabled rendering of unobserved flag bits remain unqualified.
`zstdcat` now follows the zstd alias's forced pass-through and default-stdin
behavior within the [supported decoder subset](zstd.md).

`column` preserves ragged-row padding and accepts zero output width. `colrm`
counts display columns, including tabs, backspaces and wide characters;
`col` decodes multibyte text before filtering C1 controls. `hexdump` emits no
offset for empty input or a zero byte count. These comparisons use util-linux.
`tput -T TERM` supports the seven curated terminal profiles, including common
boolean queries and profile-specific strings. It retains its custom text
sidecar format; arbitrary compiled terminfo databases remain unsupported.

`who` has focused GNU comparisons for record selection, headers, timestamps,
fixed-width strings and missing inputs using synthetic utmp files. `fincore`
matches util-linux headings, alignment and byte/human units on small private
files. Its tests check residency bounds and unit conversion without assuming
the page cache has the same state in separate invocations.

`w -h` suppresses headers; use `w --help` for help. A positional operand selects
a user. The former positional file interface is now explicit:
`w --file FILE [USER]`. Private fixtures also set `BASHW_PROC_DIR` and
`BASHW_DEV_DIR` to their process and terminal roots. Live accounting and the
procps uptime header remain outside the qualified subset. Historical benchmark
records retain their original invocation and timings; the current benchmark
driver uses the explicit file interface.

`scp [--] SRC DST` copies one local regular file, follows file symlinks, accepts
a destination directory, and rejects same-file copies before truncation.
New files use source permissions filtered by umask; existing files keep their
permissions. Local recursion and permission/time preservation are unsupported.
The remote interface retains its private transport options: `-l USER` and
`-p PORT` are not OpenSSH bandwidth and preservation options. Remote transport
has no parity claim from these local-file tests.

`ar -r` retains unrelated members and their metadata when replacing or adding
files; missing replacement inputs leave the archive intact. Empty symbol
indexes are omitted. Automatic populated-index maintenance, thin/BSD archives
and atomic recovery from a mid-write failure remain unqualified. `file`
aligns labels across operands and reports filesystem errors on stdout with
success by default; `-E` makes those errors fail. Its curated magic table is
not a complete libmagic database.

Repeated `ed` substitutions now use the correct match offsets and preserve
beginning-of-line anchors. `signal` handles Linux standard aliases and upper
realtime names without delivering signals in its lookup tests. Offline `pcap
info` rejects truncated packet data. Invalid-argument statuses are also aligned
for `apropos`, `crontab`, `split`, `unexpand`, `strings`, `taskset`, `renice` and
`lsof`; scheduler, priority and live process operations remain unqualified.

`asort` returns failure for rejected operands while continuing to sort later
valid arrays. A readonly-array diagnostic can be caught without exiting the
shell. `coreutils mknod ... p` uses the normal FIFO default of `0666` filtered
by umask; an explicit `-m` mode overrides umask without changing an existing
entry. Device-node creation remains unqualified.

`zcat` rejects empty input, preserves decoded bytes before checksum/length
errors, and decodes concatenated gzip members with bounded buffers. It follows
the reference's distinction between recoverable named-input errors and errors
that stop later operands. Trailing non-member data and the wider gzip option
interface remain outside its parity claim.

The `jq` subset accepts ordinary JSON text streams and filter files, handles
typed addition and optional type errors, and preserves successful outputs before
later evaluation errors. Independent comparisons cover Cartesian output order,
empty and multivalue conditions, and `-e` statuses. Input and output are buffered;
only one input file is supported. Full jq syntax, Unicode/NUL semantics and
general numeric precision remain unqualified. Compilation errors retain status
2, and `--stream` retains its leaf-only custom contract.

`more` matches util-linux's named-file headers on nonterminal output, directory
notices, skipped missing operands and option-error statuses. `ncdu` diagnoses
missing operands and incomplete scans instead of reporting a successful zero
total. Interactive terminal behavior is separate from these file comparisons.
`whatis` uses man-db's no-result status 16 and usage-error status 1. It retains
exact-name lookup: the observed man-db legacy text backend also matches name
prefixes, so that difference is documented as a custom contract. Help text and
implementation version banners are not compared with another project's bytes.

`strptime` retains the platform C-library interface. Selected complete calendar
dates are checked against Python; ISO week reconstruction, named timezone
interpretation and non-C locales are outside that comparison. `realpath -q`
retains its Bash-specific output suppression. These corrections do not add
every GNU long option or qualify alternate account databases and filesystems.

The custom interfaces have separate contracts. `fltexpr` recognizes `&&` and
`||`; `bashbase64` preserves completed output before an invalid suffix.
`binhex` rejects incomplete hexadecimal bytes and nonhex characters, while
`xxd` reverse mode tolerates them. `bashjson` string length counts UTF-8 bytes
and strict parsing rejects duplicate keys. A successful `cut -a ARRAY` writes
the current shell's array: use input redirection, or Bash's `lastpipe` setting,
when the caller needs the assignments after the command.

These are bounded interfaces, not complete implementations of every GNU option.
`gzip` does not implement recursive traversal, listing statistics, `-N` filename
restoration, or legacy compress formats; trailing non-gzip data is an error.
Compressed bytes need not match GNU gzip's compression choices.
`tar` uses the existing pax engine: it reads GNU long-name and PAX headers,
regular files, directories, symlinks, and hard links. Creation stores hard-linked
files as separate regular members. Device entries, sparse formats, append/update,
absolute member names, and unsafe link targets are unsupported. Its verbose
listing uses the pax format. Use `-z` to read gzip archives. Gzip tar operations
use a temporary archive file, so temporary storage must be available.
Unknown options fail explicitly. For custom builds, select both `tar,pax`;
the standalone `tar` package includes its pax implementation dependency.

`tests/gnu-command-compat.py BINARY` compares bytes and statuses against installed
GNU tools, checks exact timestamp nanoseconds, and uses independent gzip/tar
readers. All filesystem changes occur in private temporary fixtures.
`tests/bash-gnu-parity.sh` runs the broader shell and GNU utility suite visibly;
`tests/compare-parity.py` checks file contents, modes, and link relationships as
well as output and status. Diagnostic wording, version banners, archive bytes,
and unrelated GNU options are outside the byte-for-byte claim.

The reviewed JSON fixtures in `tests/loadable-parity/regressions/` add small,
repeatable comparisons for these corrections. Run them using the
[isolated parity runner](../tests/loadable-parity/FORMAT.md). It records exact
output, statuses and fixture contents, distinguishes documented custom
contracts from GNU parity, and keeps unsupported privileged, hardware and
terminal operations deferred. Each suite lists its coverage and exclusions.

The [2026-10-23 validation checkpoint](data/loadable-parity-validation.json)
records 960 passing checks across 71 suites in each of the static and dynamic
builds: 797 parity checks and 163 custom-interface contracts, with 74 deferred.
The visible shell suite also passed all 131 comparisons. The record includes
binary and fixture hashes, selected sanitizer checks, package loading gates,
and the limits of this coverage; it adds no performance measurements.

The [second validation checkpoint](data/loadable-parity-validation-2.json)
extends this to 1,313 passing checks across 107 suites in each canonical build,
with 147 deferred cases. It also records 270 sanitizer checks, 26 package
loading gates and the maintained clear suite. The disposable Docker comparison
passed all 131 cases. No new command timings are recorded.

The [third validation checkpoint](data/loadable-parity-validation-3.json)
records 1,506 passing checks across 123 suites in each canonical build,
with 173 deferred cases. It includes 154 sanitizer checks, 16 package loading
gates, and 40 maintained `more` checks plus its focused smoke assertion.
The updated Docker image passed all 131 comparisons against the unchanged
namespace-isolated GNU reference. These runs add no performance measurements.
