# index: behaviour, coverage and performance

`index` reads and changes git's `.git/index`. The format code it shares with
the `git` builtin lives in `loadables/_git/index.c`; `loadables/index.c` is
the command surface and adds the checks, edits and locking described here.

## What it reads

The listing reader accepts versions 2, 3 and 4 and follows Git 2.47.3's
leniency for padding, name-length fields, entry order, duplicate stages,
paths, ordinary trailers and optional extension sizes. Unknown mandatory
extensions and unknown extended entry flags fail before output. Bounds
checks use owned memory. Git maps the index in whole pages and treats the
bytes from the end of the file to the end of that page as zeroes. Those
bytes are part of the deterministic result, and a listing that uses them
matches Git's output and exit class. This includes a single entry whose
declared name reaches the last byte of the page, and a `0xFFF` name with
no interior NUL when the file itself is an exact page.

A read at or past the end of that page is refused with an error, a nonzero
status and no listing. Git's behaviour there is not defined: the same
bytes do not produce one listing or one exit status. The measured shapes,
with the name field beginning at offset 74, are:

- version 2 or 3, count of at least 2, and a first entry whose 12-bit name
  length is `page_size - 74`. The next header starts past the page.
  Repeated `git ls-files --stage` runs print different listings. On a
  4096-byte page that length is 4022.
- version 4, count of at least 2, a first entry whose 12-bit name length
  is 4000, and a single `0x00` strip byte with no suffix. The declared
  field places the next header past a 4096-byte page. Repeated runs mix a
  successful listing with status 128 and do not repeat one listing.

The same refusal applies to any later entry whose header would start at or
past the page, including a version-4 suffix span of `(flags & 0xfff) + 1`
minus the prefix taken from the previous name. A last entry is still
listed from the bytes that fall inside the page. Strict checks still apply
only to writes. This page-overrun refusal is a stated difference from Git,
not an open contract: repeated `git ls-files --stage` runs do not produce
one listing or one exit status.

Where Git 2.47.3's listing is deterministic, the reader matches it.

- An EWAH bitmap's `bit_size` and RLW index are ignored. `ewah_each_bit`
  walks the words from the start and never reads those fields. A set bit
  at or past the shared index is Git's `fatal: position for delete` or
  `fatal: position for replacement`, with no listing.
- A literal count past the words stored in the extension is the read
  `ewah_each_bit` performs past the bitmap it copied. On a two-word
  bitmap that copy is 16 bytes, and the position in Git's
  `fatal: position for delete` or `position for replacement` is the
  first set bit of the allocator word that follows. It is not a field
  of the index. The delete bitmap in
  `tests/fixtures/sol-index-parity/indexes/v3-split-literal/` prints
  position 69 when the index path is 46 bytes and position 72 when
  that path is 80 bytes; repeated runs at one path length stay on one
  position. Git prints no listing and exits 128. Once the walk has
  already reached the shared index, that overrun is refused and the
  bytes are not read. Any other literal overrun stops the walk.
- An entry marked both deleted and replaced is replaced and then dropped.
  Git lists that index; it does not die on the pair.
- A sparse directory whose tree object cannot be read is omitted. The
  diagnostic is `error: invalid object 040000 <oid> for '<name>'` followed
  by `error: Could not read <oid>`. The name has no trailing slash. The
  remaining entries are listed and the status is 0.
- A version-4 strip varint that overflows is 0 and does not advance, so
  the name is read from the varint's first byte. That is `decode_varint`.
- A version-4 name shorter than the prefix copied from the previous entry
  is the overlap copy Git's allocator performs. The listing matches
  `git ls-files --stage` for that index path. A copy that would load
  outside the mapped page or the cache pool, or that would leave an object
  id algorithm other than SHA-1, is refused with no listing. On the
  measured indexes of that shape, Git 2.47.3 either crashes with SIGSEGV
  or exits 128 before printing a listing. Those reads are not performed.

A mode `040000` directory entry is expanded in place even when the `sdir`
extension is absent, truncated, renamed or shifted. Expanded entries keep
index order. A directory that is not skip-worktree produces Git's
`warning: index entry is a directory, but not sparse (<flags>)`. A
directory whose tree cannot be read is still omitted, as above.

A replacement whose stored name length is not zero, or an addition whose
stored name length is zero, is Git's
`fatal: corrupt link extension, entry N should have zero length name` or
`should have non-zero length name`. The length is the 12-bit field, or the
C-string length when that field is `0xfff`. It is not the position of the
first NUL. `fatal: index cache-tree records empty sub-tree` is the same
die as `cache_tree_update` when a subtree consumes no entries. A mode
`040000` directory whose stored length equals that base does not die.
These fatals print the `fatal:` line and no listing. The status is 1, the
status this command uses for a reported error.

An `UNTR` extension whose declared body is longer than one byte and whose
declared end is past the mapped page is refused with no listing.
`read_untracked_extension` sets `end` to the declared size and loads
`end[-1]`. The measured case is an `UNTR` size of 1795293976 in a
1984-byte index: `git ls-files --stage` dies with SIGSEGV on every run,
with empty output. A declared size that ends inside the zero-filled page
tail is not refused. `TREE`, `REUC`, `link` and `FSMN` stop on a remaining
size, and a sparse listing discards `TREE` before reuse, so a large
declared size on those extensions is not a refusal by itself. `sdir`,
`EOIE`, `IEOT` and unknown `A`–`Z` extensions are not read past their
header.

Split indexes resolve `link` against `sharedindex.<hash>` in the repository,
apply the replacement bitmap and then the deletion bitmap, and merge local
additions. Missing or corrupt shared files fail before output or
replacement. Sparse indexes expand directory tree IDs through the existing
object database, including packed objects, and retain skip-worktree on
expanded entries. Repository-dependent formats use repository discovery or
the index's parent git directory; no external Git command is invoked.

Changing verbs validate the resulting paths, flags and sorted unique stages.
A change writes an ordinary v2/v3 index containing the expanded entries;
an unchanged import preserves the original split/sparse representation.
`--index-info` also accepts directory records and emits `sdir`, as Git does.

Optional extensions (TREE, REUC, UNTR, EOIE, IEOT, FSMN) are allowed when
reading. `read`/`list` print `<mode> <sha> <stage> <path>` with the mode in
at least six octal digits, as `git ls-files --stage` does. The output
goes straight to the descriptor in 64 KiB writes. A write error is reported
and gives status 1, and stdout is still usable afterwards. `-V VAR` binds
an array instead. It checks the name and whether the variable is readonly
before reading, and leaves VAR alone when the read fails.

## What it changes

`write`, `--index-info`, `add`, `remove` and `update-stat` take
`PATH.lock` with `O_CREAT|O_EXCL` before the read and hold it until the new
file has been renamed into place. That is git's protocol, so neither this
command nor a concurrent git can lose the other's update. The new index is
written to a temporary file, fdatasync'd and renamed. Any write, short
write, fdatasync, close or rename failure leaves the old file and no lock or
temporary file.

- `--index-info [-z]` takes all three record shapes `git update-index
  --index-info` takes. It unquotes C-quoted paths, removes every stage of a
  path given mode 0, normalises modes as git does and applies git's path
  rules (bad paths are ignored with a message). It also handles D/F
  replacement and lets a stage-0 entry displace the path's conflict stages.
  An index nothing changed is left untouched.
- A rewrite uses version 3 when extended entry flags are present, otherwise
  version 2. It keeps the old index's resolve-undo (REUC)
  records and adds a record for each conflict stage it removes, as git
  does. TREE, UNTR, FSMN and EOIE/IEOT are caches git rebuilds and are
  dropped. Skip-worktree and intent-to-add flags survive unrelated edits;
  an empty input leaves even an extended-flags index byte-for-byte untouched.
- Racy entries, whose mtime is not before the old index's, are settled as
  git settles them. The file is compared by content, and the entry gets
  size 0 only if the content differs from its id.

## Coverage

| test | what it holds the command to |
| --- | --- |
| `tests/sol-index-check.py` | 26 cases against host git 2.47.3 on private repositories: `ls-files --stage -z` output for small, 20000- and 110000-entry indexes, cold and warm; long paths (0xFFF boundary, 8 KiB, 70000 bytes past the 64 KiB buffer); stage order; v3 and every optional extension; Git-written split/sparse/v4; every truncation and single-byte change of a small index; 33 crafted structural cases under a valid trailer; 500 seeded mutations, agreeing with Git wherever Git's result is deterministic, and refusing an entry whose next header would start past the mapped page; accepted output must equal Git; `write` byte-identical to git; `--index-info` byte-identical to git on scripted, seeded-random and 20000-record streams, with the same exit class; `add`/`remove`/`update-stat` field-for-field against `update-index --add/--force-remove/--refresh`; lock honoured by every verb; unwritable directory; injected failures; repeated calls in one shell with a constant descriptor count; empty PATH throughout |
| `tests/sol-index-formats.py` | Git-written split, core.splitIndex, cone sparse and v4 indexes through every changing verb; shared-file failures preserve bytes and release locks |
| `tests/sol-index-faults.c` | LD_PRELOAD shim that fails write, short write, fdatasync, close or rename on the index's temporary file |
| `tests/sol-index-fuzz.c` | libFuzzer over the production `index.c`: reader → checks → write → reread round trip, `--index-info` application (order and path invariants, REUC round trip) and `write` line parsing |
| `tests/sol-index-sha1.c` | the trailer SHA-1 against the FIPS 180-2 vectors and against SHA1DC at every length 0–4100 and over 1 MiB at each alignment 0–7, under ASan/UBSan |
| `tests/index-cache.py`, `tests/final-smoke.py formats` | existing checks, unchanged, still pass |

`tests/sol-index-build-fixtures.sh DEST` builds the shim, the SHA-1 check,
the fuzzer and an ASan/UBSan build of the builtin (`DEST/load.sh`). Run it
through the build gate after a targeted `./build.sh --include index`. Then:

    python3 tests/sol-index-check.py --binary out/bash-sol-index --shim DEST/faults.so
    python3 tests/sol-index-check.py --binary out/bash-sol-index --shim DEST/faults.so \
        --loader DEST/load.sh --asan "$(cat DEST/asan-path)"
    DEST/sha1-check
    SOL_INDEX_FUZZ_DIR=$(mktemp -d) DEST/fuzz -max_total_time=300 CORPUS

## Performance

The historical catalog row put `index read` at 1.93× `git ls-files
--stage` (78.7 ms against 40.9 ms per five reads, 2026-09-12 snapshot,
another build). That is not a paired result with anything here.

### Historical measurements before listing compatibility

`bench/sol-index-prof.c` includes the production `_git/index.c` and times
its phases. Medians of 101 repetitions on CPU 11, for a git-ordered 20000-entry,
1760032-byte index:

| phase | µs |
| --- | ---: |
| whole read, trailer computed (cold) | 6873 |
| whole read, trailer matched against the verified snapshot (warm) | 1001 |
| file read | 138 |
| trailer with SHA1DC, as before | 8099 |
| SHA1DC with collision detection off | 5691 |
| trailer with the plain SHA-1 now in `_git/index.c` | 4961 |
| path checks for all entries | 456 |

The trailer hash was most of a cold read, and SHA1DC added about 3 ms
of collision detection to a checksum that authenticates nothing. git does
not verify that checksum on an ordinary read at all. At that revision the trailer was still
verified, using a plain FIPS 180-4 SHA-1. `tests/sol-index-sha1.c`
checks it against the FIPS vectors and SHA1DC. Object ids still use SHA1DC.
The rest came from output. The builtin used to hand 64 KiB chunks to
bash's line-buffered stdout, which glibc still flushes in small pieces:
`strace -c` counts 1277 `write` calls per 20000-line read before and 22
after, since output now goes to the descriptor 64 KiB at a time. The old
path also cut every printed path at about 8 KiB; the new one prints paths
of any length. An index above the 8 MiB snapshot limit is hashed on every
read.

### Measured

`bench/sol-index.py` uses indexes written by host git 2.47.3. Each case
first runs a batch where every pass's output and status are checked
against `git ls-files --stage`, or for `--index-info` the written file is
compared byte for byte. Then come a discarded warm-up batch and nine timed
batches of five calls in one shell pinned to CPU 11. Times are median ms
per batch of five. "Cold" alternates between two same-size files that
differ in one id, so every pass computes the trailer. git verifies no
trailer at all.

| case | before (d77e24a) | after | git (in the "after" run) | after / git |
| --- | ---: | ---: | ---: | ---: |
| small, 100 entries, warm | 0.371 | 0.149 | 6.569 | 0.02 |
| small, cold | 0.553 | 0.221 | 6.908 | 0.03 |
| large, 20000 entries, warm | 16.53 | 8.80 | 46.23 | 0.19 |
| large, cold | 49.96 | 25.04 | 50.77 | 0.49 |
| xlarge, 110000 entries (8.8 MB), warm | 309.0 | 157.2 | 204.0 | 0.77 |
| xlarge, cold | 310.9 | 151.6 | 252.6 | 0.60 |
| `--index-info`, 20000 records into a new index | — | 275.3 | 256.7 | 1.07 |

Both binaries were measured back to back on the same host, from the same
fixtures (SHA-256 recorded in the reports), at 1-minute load 4.3–4.8. Before
the change the 110000-entry read was 1.30× git; after it, 0.60×.

The `--index-info` case writes and fdatasyncs a new index on every pass.
git does not sync the index by default. On this ext4/NVMe scratch
directory, `strace -T` puts the fdatasync at a median of 1.5 ms per call,
about 7.7 ms of the 18.5 ms difference per batch. The rest could not be
attributed further, because the host forbids `perf` (`perf_event_paranoid`
3).

### The historical fixture

`bench/loadables.py` builds its index fixture in generation order, not path
order. Earlier revisions refused it; the listing-compatible reader now
accepts it and the dedicated benchmark verifies its output against Git.
The shared benchmark file remains unchanged. Sorting its fixture is an
optional coordinator change to model writer-produced indexes, no longer a
requirement for this command to read it.

A non-removal entry with the null object ID is refused at final write, before
replacement. An intermediate null-ID record removed later in the same
`--index-info` stream is allowed; mode-0 removal remains a valid no-op for
an absent path. Failed final validation preserves the old index and releases
the command's lock.

The command-specific suite requires listing parity in both directions,
except the mapped-page overruns above, which are expected refusals.
The 33 structural cases include the 20 former strict-read differences and
the two formerly unsupported required extensions. Successful imports are
also read back and compared with Git. The regression suite retains stage,
null-ID and extended-flag coverage. Output failures use an injected write
interface on owned regular files.

### Correction to the historical cold measurements

The original five-pass cold schedule restarted at A for each batch, so the
20000-entry case contained one checksum-cache hit and four misses per batch.
Those preserved reports measure mixed-cache batches, not five cold reads.
The corrected schedule carries its A/B position through warm-up and every
batch. Its work-count regression checks 40 successive invocations. Each
warm-up and timed pass now captures output to an owned regular file and is
checked against the corresponding Git oracle; import files are also checked
for every pass. Timings include output-file writes; validation happens after
timing, so these new measurements must not be compared directly with old
`/dev/null` timings as a code speedup. The 110000-entry index exceeds the
checksum snapshot limit and computes its checksum on every pass in either
schedule.

The preceding measurements and checksum counts describe the preserved
historical revisions. The listing-compatible revision omits ordinary-read
checksum work, as Git does; shared-index verification and outgoing trailers
still use the index-only plain SHA-1. Object IDs continue to use SHA1DC.
New measurements retain the same continuous A/B schedule and output checks.
