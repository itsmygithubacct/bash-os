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

`touch -d` and `--date` accept `@SECONDS` with an optional sign and decimal
fraction, including dates before the epoch. Fractions are represented as integer
nanoseconds. `cat --` ends option parsing; `cat` also supports the common GNU
numbering, blank-line squeezing, and nonprinting-byte display options.

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
