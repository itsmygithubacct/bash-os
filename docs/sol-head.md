# head option and performance completion

Private stdin descriptors start above stderr. `tests/review-head-descriptors.py` checks that closed output fails without overwriting read/write stdin, for byte, line, header and negative-count modes.

The measurements below predate this review correction. They describe the original
worker implementation; they are not measurements of the corrected code. No new
performance claim is made for this correction.

`head` extends the pinned Bash example through
[`patches/head-stdin.patch`](../patches/head-stdin.patch). The build still uses
`examples/loadables/head.c`; there is no replacement loadable or generated
source to maintain. No common helper changes or libraries are required.

The command supports `-n`/`--lines`, `-c`/`--bytes`, zero and signed counts,
GNU numeric multipliers, `-q`/`--quiet`/`--silent`, `-v`/`--verbose`, and
`-z`/`--zero-terminated`. `--` terminates options; options can follow file
operands. A first argument of the historical `-NUM[bkm][clqvz]` form is also
accepted. Long options accept unambiguous abbreviations. `--help` describes
the builtin and `--version` identifies it as a Bash loadable.

Positive counts copy at most N records or bytes. Negative counts copy all
except the last N records or bytes. A trailing unterminated record counts
as a record; embedded NULs remain data unless `-z` selects them as delimiters.
Counts saturate instead of wrapping when they exceed `uintmax_t`, matching
GNU's behavior for counts larger than the input. Malformed counts fail before
opening operands. Counts and options are reset on every invocation.

Default headers appear for multiple operands, including repeated `-` operands.
They identify `-` as `standard input`; quiet suppresses them and verbose forces
them for a single input. Failed opens do not introduce header separators.
GNU head's positive line mode can discard pipe read-ahead between repeated `-`
operands. This builtin preserves it: `head -n1 - -` on `a\nb\n` prints both
records under their respective headers. That deliberate difference follows the
persistent-shell exact-consumption contract; byte mode and seekable input can
be compared directly with GNU.
Read/open/write failures accumulate across files and return failure, and stdout
is flushed and its error flag cleared before returning to the persistent shell.

Each input owns a private `FILE` and descriptor. Standard input is duplicated;
an opened file is owned even if its descriptor number is zero. Seekable input
returns stdio read-ahead before closing, preserving the next reader's offset.
Positive line counts use block scanning on seekable input and unbuffered input
on pipes, so an open producer cannot make a fulfilled first-N request wait.
Byte counts read only the requested byte count. These lifetime guarantees and
sed's separate compatibility limits remain in [head-sed.md](head-sed.md).

Tail exclusion scans backward on nonempty regular files and then copies the
prefix in blocks, leaving seekable stdin at the prefix boundary. GNU also
preserves that boundary on its optimized regular-file paths, but can consume a
read-ahead block when a large excluded tail leaves no output. This builtin
retains the entire excluded suffix for the next reader in that case as well.
Pipes use a queue of chunks and consume to EOF. Memory grows with the bytes
actually retained in the excluded suffix, including an unfinished record; it
does not allocate N elements just because the count is large. Inputs reporting
zero size, including procfs streams, use the streaming path. Live mutation of
an input file and asynchronous signal interruption are outside the focused
conformance claims.

The focused native build includes `head,sed,fold,expand,nl,pr,tac,bc` to run the
existing head/sed and mixed-reader suites. Head alone needs no companion;
`sed` is needed for `tests/head-sed-parity.py`, and the remaining commands are
needed by `tests/input-lifetime.py`. The selection resolves to the existing
`_jsmn` helper without any helper changes.

Validation commands (run compilation and timing under the required resource
gates in a coordinated campaign):

```sh
./build.sh --include head,sed,fold,expand,nl,pr,tac,bc --name sol-head
python3 tests/sol-head-options.py out/bash-sol-head
python3 tests/head-sed-parity.py out/bash-sol-head
python3 tests/input-lifetime.py out/bash-sol-head
bash tests/sol-head-sanitize.sh out/bash-sol-head
bash tests/head-sed-sanitize.sh out/bash-sol-head
python3 bench/sol-head.py --binary out/bash-sol-head \
  --before out/bash-sol-head-before --runs 7 --output /tmp/sol-head.json
```

The new option suite compares stdout bytes and statuses with installed GNU
head, tests both regular files and pipes, retains binary records, inspects
shared descriptor offsets, keeps a producer open for early-stop checks, and
checks repeated errors and recovery under a low descriptor limit with an empty
PATH. The sanitizer suite compiles the actual patched production source as a
module and runs the same assertions in a real Bash process. Existing suites
retain their assertions.

The task-owned benchmark reproduces the historical 423,000-byte text fixture
and 78 calls to `head -n 100`, then measures byte-prefix and large tail-exclusion
work separately. Its 32 MiB binary fixture contains 524,288 fixed-width records;
large exclusions emit a validated 16 MiB prefix per call. Every invocation
checks status; single-call validation, warm-up and all seven timed batches
check exact output bytes against an independent Python oracle and GNU. Output
is captured into a temporary file for every timed batch. This includes output
I/O and is a different measurement method from historical `/dev/null` timings.
The report records fixture/source/binary hashes, affinity, versions, options,
passes and complete sample distributions. It does not alter historical reports.

## Validation and measurements, 2026-10-19

The native binary passes 1,174 new head checks, all 974 existing head/sed
checks, and all 156 mixed-reader checks. The instrumented production head
passes the 1,174-check suite under ASan/UBSan; instrumented head and sed also
pass the unchanged 974-check suite. Tests run with an empty PATH and GNU head
9.7 as the head byte/status reference. Static-rootfs and cross-libc integration
remain coordinator-level checks; this task qualifies the native software path.

Measurements used an Intel Core i7-9850H, fixed CPU 11, Linux
6.12.111+deb13-amd64, Bash 5.3.15, GCC 14.2.0, and GNU coreutils 9.7. Both
native builds use the same eight-command selection, dynamic linking,
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, and stripping. The final
binary SHA-256 is
`16e4015fcf6d64aa1286ea88dd9ecdfd55eb7f2cc11afd97b7be7f766df3d1d3`.

Each cell gives batch median milliseconds (minimum–maximum), across seven
samples after warm-up. Every timed batch validates captured output bytes and
every invocation checks its status. These figures include shell startup,
redirections, output to a temporary file, and GNU fork/exec costs. The pipe
case includes the same external producer for each implementation.

| Workload | Calls | Builtin ms | GNU ms |
|---|---:|---:|---:|
| First 100 lines, 423,000-byte text | 78 | 5.603 (5.012–5.745) | 51.381 (44.787–54.979) |
| First 65,536 bytes, 32 MiB binary file | 8 | 2.780 (2.604–3.579) | 8.094 (7.966–11.907) |
| Exclude 262,144 lines, 32 MiB binary file | 3 | 57.949 (52.850–60.868) | 52.989 (48.343–55.516) |
| Exclude 16 MiB, 32 MiB binary file | 3 | 29.569 (26.983–31.737) | 40.079 (37.174–42.683) |
| Exclude 262,144 lines, 32 MiB binary pipe | 1 | 35.804 (35.175–42.095) | 47.547 (46.677–53.168) |

The same-run baseline for the 78-call first-N case was
10.857 (9.877–12.169) ms. An earlier baseline reproduction was
11.461 (9.128–12.631) ms against GNU's 48.652 (43.444–53.160) ms, with all
bytes validated. The fixture matches the historical SHA-256
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`;
each call emits 5,217 bytes. No first-N slowdown against GNU remained to
profile. Block input scanning and block output reduce the old per-byte
stdio work while preserving exact consumption.

Each large exclusion emits 16,777,216 bytes per call. Regular line-tail
exclusion takes 1.09 times GNU's batch time in this run; the byte-tail and
pipe line-tail cases take 0.74 and 0.75 times GNU's time. The separate cases
show why a first-N result cannot describe tail exclusion. These are matched
command workloads with validated bytes, not throughput claims for every
record width or suffix size. The complete distributions, fixture hashes,
versions, source hashes, binary hashes and raw validation logs are preserved
in the task evidence directory; historical reports are unchanged.
