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
dot entries, recursive headings and invalid-option status on ordinary private files. Attribute-setting
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

The `zlib` decoder also preserves decoded prefix bytes returned alongside an
integrity error. Its codec fixtures distinguish round-trip-result comparisons
from independent fixed decoder vectors; self-generated compressed artifacts do
not establish external format interoperability.

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
`less` concatenates file payloads without separator headers when plain output
is redirected. In that mode, file-open errors appear on stdout, later operands
are still read, and file-open errors alone leave status 0, matching less 668.
Its interactive path remains unqualified by these fixtures.
`whatis` uses man-db's no-result status 16 and usage-error status 1. It retains
exact-name lookup: the observed man-db legacy text backend also matches name
prefixes, so that difference is documented as a custom contract. Help text and
implementation version banners are not compared with another project's bytes.

`ssh known-hosts list` and `remove` have offline comparisons with OpenSSH
`ssh-keygen` using private files. Literal comma-separated aliases match without
case sensitivity; removal preserves the original in `FILE.old`, keeps ordinary
permission bits, and reports updates on stdout. No-match removal leaves the
file unchanged, while a missing file returns 255. Marker records, wildcard
patterns, concurrent replacement and remote SSH behavior remain unqualified.

`script record` writes raw payload logs without util-linux's timestamped
transcript wrappers. `script replay` consumes those raw logs and reports short
input, invalid numeric timing fields and output errors. Byte-preserving replay,
append/truncate recording and child statuses have explicit custom contracts;
they are not timestamped typescript-file parity. Interactive resize, timing
accuracy and cast output remain outside these comparisons.
Explicit echo mode is configured before the recorder forwards input to its
private PTY. Advanced H/S timing metadata is skipped rather than validated.

`wget_wch read` assembles complete UTF-8 scalars before deciding cluster
boundaries and retains the following scalar. Seekable input is rewound;
nonseekable input uses process-local lookahead. Drain each nonseekable input
with this builtin in one shell process: mixing readers, sharing reads across
forks, or reopening the same FIFO/terminal with pending lookahead is unsupported.
Closing an undrained stream retains a cache slot until shell exit, and failures
can consume input. These are bounded Unicode contracts, not full grapheme or
terminal-input parity.

`wall -h` and `--help` print its own documentation without broadcasting.
Invalid options and missing or invalid timeout arguments return status 1.
Timeout values are parsed but synchronous terminal writes do not enforce a
deadline. Broadcast behavior has no operational parity claim from these tests.

`awk` honors assignments to `NR` and `FNR`, including compound updates and
increments, and resets `FNR` for each named input file. Focused comparisons
use GNU gawk and cover both expression evaluation paths. Existing differences
in counters updated by explicit-file and command-pipe `getline`, and broader
language and numeric limits, remain outside that claim.

`bc` treats bare operands as filenames, including missing paths and `-`.
Expressions use `-e`, and explicit stdin uses `-f -`. Ordinary stdin/file runs
return GNU's status 0 after recovered syntax or runtime errors; `--strict-errors`
and the existing `-e`/`-f` extensions retain status 1. File-open, input/output
and reported resource failures still return 1. A malformed multi-statement
syntax-recovery difference remains a strict failure; see [bc](bc.md).

`git cat-file` distinguishes an unresolved name from a missing full object ID
across type, size, existence, pretty-print and explicit-type queries, including
their statuses and diagnostics. `strings` matches GNU's missing-file and
non-directory-path diagnostics, including names with spaces or quotes. Its
invalid-radix help text remains different because the supported options differ.

`cksum` retains the name `-` for explicit standard-input operands; implicit
standard input has no CRC filename. Invalid algorithms and options return
status 1, and repeated calls reset the selected algorithm and delimiter.

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

`gzip` follows an input symlink only in filter mode or with `-f`; an unforced
named symlink returns status 1, including under `-q`. A multiply linked regular
input returns warning status 2 unless `-f` is used. Forced symlink compression
removes the link entry after successful publication and retains its target.
These checks cover stable private paths, without a concurrent replacement claim.

`nano -h` and `--help` print the builtin's own documentation. Invalid options
and fill arguments return failure status 1. Without terminal input and output,
the editor fails before loading a file or drawing a screen; its help and
nonterminal output have explicit contracts rather than GNU screen-output parity.
`slabtop` also returns failure for invalid options and missing option arguments.
It fails if its selected slabinfo input is unavailable. Its focused fixtures
use synthetic proc data and do not qualify live counters.

`utf8` normalization, case folding and codepoint counting replace each maximal
subpart of an ill-formed UTF-8 sequence once. The focused tests do not qualify
every Unicode operation or table. In `vi` scripted editing, `a` advances past
the complete UTF-8 character before inserting. Uppercase `A` appends at the
end of the current line and can be repeated with `.`.

`wg` rejects IPv4 prefixes above 32 and IPv6 prefixes above 128, along with
nondecimal prefix text. These checks exercise its offline dry-run parser;
network interfaces and kernel communication remain unqualified. `pcap info`
accepts classic microsecond and nanosecond files in either byte order, with
independent fixture headers and records. Live packet capture remains deferred.

`pathchk` rejects an empty pathname in both default and `-p` modes. `column`
returns failure status 1 for invalid output widths. Repeated `man` renders read
fresh redirected input even after a previous call reached EOF. `bashbase64`
emits the final bytes of unpadded groups and rejects a one-character tail;
its whitespace, leading-tag and URL-alphabet extensions remain documented.

`mkswap` checks requested size against the available file size unless `-f` is
used, validates complete canonical UUIDs, truncates labels to 15 bytes with a
warning, and reports usable bytes excluding the header page. Its selected
util-linux comparisons use small zero-filled regular images and fixed UUIDs.
Page sizes are restricted to powers of two from 2048 through 65536 bytes;
only 4096-byte pages were exercised. Raw devices, swap activation, random UUID
generation and I/O failure recovery remain unqualified.

`ln` accepts `-n`/`-h` when replacing a symlink to a directory and returns a
single failure status across multiple failed operands. `chgrp`, `setsid` and
`expand` return the reference utility's status for their selected argument errors.
`rmdir --ignore-fail-on-non-empty` suppresses nonempty-directory errors while
preserving missing-path and wrong-type errors. `rm -i` reads confirmations from
standard input; the last `-f` or `-i` wins. Its bounded fixtures cover ordinary
files and small recursive trees, without terminal or localized-prompt coverage.

`zstd --no-content-size` omits the original size field in compressed frames.
Its options must precede file operands. `utf8 slice` returns an empty string
when a codepoint or grapheme start is at or beyond the end. `whatis` keeps its
documented exact-name lookup; the installed man-db backend also matches prefixes,
so that behavior remains an explicit compatibility difference.

`bashkmod weak-modules` creates usable relative links inside an explicitly
selected module tree. Its tests use synthetic files and do not load modules.
`bashmount --mountpoint` returns status 32 for an existing non-mountpoint;
the fixtures only query private files and directories. `fdisk` preserves the
documented default type 05 for an extended partition and 83 for a logical
partition when the type field is omitted or empty. Its custom-interface checks
decode small private regular images; real devices and kernel updates are excluded.

`bashinotify wait -n` retains unreported events for the next call; closing the
watch clears that queue. `setfacl` uses a symlink target's mode when creating its
base ACL and returns status 2 for invalid ACL text. `coreutils shred -x` and
`--exact` accept exact-size operation, which is also this implementation's
default. The tests compare small private files after a zero pass and establish
no physical-erasure guarantee.

`stat` applies byte precision to strings and minimum digit precision to
integers, including width and zero-padding interactions. Its selected `%N`
cases match GNU quoting for ordinary apostrophes; fractional timestamp
precision and control-character quoting remain outside this coverage.
`flock` uses util-linux's usage, descriptor, open and timer-error statuses,
checks command arity before opening files, and treats a numeric operand as a
filename when followed by a command. Tests use private locks and bounded children.
`pgrep` accepts a trailing selector comma, and `sync` rejects unknown options
with status 1 before attempting synchronization.

`getfacl` includes effective-permission comments for restrictive masks and
shows access and default ACLs together unless a selection flag is supplied.
Its mode fallback follows symlink targets. `tinfo` reads the separate name-offset
table in the [ncurses extended terminfo format](https://www.invisible-island.net/ncurses/man/term.5.html),
including ordinary cancelled-string records. Independent `tic`/`tput` fixtures
cover those records; this does not qualify every database or terminal operation.

These are bounded interfaces, not complete implementations of every GNU option.
`gzip` does not implement recursive traversal, listing statistics, `-N` filename
restoration, or legacy compress formats; trailing non-gzip data is an error.
Compressed bytes need not match GNU gzip's compression choices.
`tar` uses the existing pax engine: it reads GNU long-name and PAX headers,
regular files, directories, symlinks, hard links and FIFO metadata. Creation
preserves regular hardlinks across recursion and `-C` operands when member names
do not conflict. Conflicting names can make a later hardlink bind to replacement
data, matching GNU tar; source topology across such collisions is not preserved.
Device entries, sparse formats, append/update,
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

The [fourth validation checkpoint](data/loadable-parity-validation-4.json)
records 1,712 passing checks across 143 suites in each canonical build:
1,193 reference comparisons and 519 custom contracts, with 221 deferred cases.
It includes 83 sanitizer checks, 16 package loading gates and 131 passing
Docker comparisons. These results cover the same fixtures in both builds;
the two pass totals are not independent coverage or performance measurements.

The [fifth validation checkpoint](data/loadable-parity-validation-5.json)
integrates all 289 reviewed suites with 3,806 cases. Each canonical build has
3,155 passing checks, 28 failing comparisons, 23 optional-module skips and
600 deferred cases. These totals incorporate 19 ACL comparisons run in a second
reference environment with identical binary and fixture hashes; existing
metadata passes are counted once. The 167 focused regression suites separately
pass 2,076 checks with 260 deferred, and overlap the full reviewed set.

Strict differences remain for `apropos`, `bc`, `binhex`, `getconf`, `git`,
`logname`, `nano`, `sftp`, `strings`, `whatis` and `whoami`. They include custom
interfaces, diagnostics, help/version text and configuration inventory output;
the record lists each failing case. The reviewed fixtures retain these
comparisons. Corrections to stale contracts and fixture setup are recorded
separately from production fixes.

The same static binary passed all 131 Docker comparisons. Separately loaded
Perl and Python modules and uv metadata passed 23 checks against the canonical
dynamic shell, with eight deferred operations. Those module checks do not
make the optional modules available in the bare binaries or Docker image.
Selected sanitizer and package evidence includes explicit source, fixture and
dependency-provenance limits. No new performance measurements are recorded.

The [0.1.2 validation record](data/release-0.1.2-validation.json) covers 289
suites and 3,818 cases in each new static and dynamic binary: 3,171 passes,
24 strict failures, zero harness errors, 23 optional-module skips and 600
deferred cases. Matching ACL checks replace 19 missing-reference skips in each
build. The overlapping focused set has 2,088 passes, one strict failure and
260 deferred cases across 167 suites; its totals must not be added to the full
set.

Five of the 0.1.1 failures are fixed: the three `bc` file/status cases, the
missing Git object diagnostic, and the absent-file `strings` diagnostic. The
23 retained baseline differences remain strict failures. A newly added `bc`
syntax-recovery comparison exposes a difference that also reproduces on the
0.1.1 binary; both fixture sets retain it as a failure. The record lists the
disposition of all 28 baseline failures and pins the changed source and
fixtures. Earlier Docker, optional-package, cross-architecture and sanitizer
results are historical and are not new qualification for the 0.1.2 binaries.
