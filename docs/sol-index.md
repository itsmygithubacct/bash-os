# index: behaviour, coverage and performance

`index` reads and changes git's `.git/index`. The format code it shares with
the `git` builtin lives in `loadables/_git/index.c`; `loadables/index.c` is
the command surface and adds the checks, edits and locking described here.

## What it reads

An index is read whole and checked before anything is printed or changed.
The shared reader checks the header (`DIRC`, version 2 or 3, entry count),
each entry's framing, the 0xFFF path-length field, NUL padding to eight
bytes, git's path rules and the SHA-1 trailer. The command then refuses:

- an extended-flags bit in a version 2 entry, or a version 3 second flags
  word with bits other than skip-worktree and intent-to-add;
- entries out of path order, a repeated (path, stage), or stages out of
  order. Stage 0 beside a later conflict stage is accepted: Git's
  `update-index --index-info` can produce it, and subsequent reads and
  removals must consume it;
- extension records that do not exactly fill the space before the trailer;
- an extension whose signature does not start with a capital letter, which
  git marks as required. That covers a split index (`link`) and a sparse
  index (`sdir`), which this command cannot honour. Version 4 is refused.

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
- A rewrite is version 2. It keeps the old index's resolve-undo (REUC)
  records and adds a record for each conflict stage it removes, as git
  does. TREE, UNTR, FSMN and EOIE/IEOT are caches git rebuilds and are
  dropped. A version 3 entry marked skip-worktree or intent-to-add is
  refused for editing rather than silently losing the bit.
- Racy entries, whose mtime is not before the old index's, are settled as
  git settles them. The file is compared by content, and the entry gets
  size 0 only if the content differs from its id.

## Coverage

| test | what it holds the command to |
| --- | --- |
| `tests/sol-index-check.py` | 25 cases against host git 2.47.3 on private repositories: `ls-files --stage -z` output for small, 20000- and 110000-entry indexes, cold and warm; long paths (0xFFF boundary, 8 KiB, 70000 bytes past the 64 KiB buffer); stage order; v3 and every optional extension; refusal of split/sparse/v4; every truncation and single-byte change of a small index; 33 crafted structural cases under a valid trailer; 500 seeded mutations, each of which must be refused or read as git reads it; `write` byte-identical to git; `--index-info` byte-identical to git on scripted, seeded-random and 20000-record streams, with the same exit class; `add`/`remove`/`update-stat` field-for-field against `update-index --add/--force-remove/--refresh`; lock honoured by every verb; unwritable directory; injected failures; repeated calls in one shell with a constant descriptor count; empty PATH throughout |
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

### Where the time went

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
not verify that checksum on an ordinary read at all. The trailer is still
verified, now with a plain FIPS 180-4 SHA-1. `tests/sol-index-sha1.c`
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

`bench/loadables.py` builds its `index-read` fixture in generation order.
That is not path order (`dir000/file-00256.txt` follows
`dir255/file-00255.txt`), and gitformat-index requires path order. git reads
the file without checking. This command now refuses it with "unordered index
entries", so that harness reports `bashos=error` for the case. The
`large` fixture here holds the same 20000 entries, ids and file size,
byte-identical to that fixture sorted. It is also exactly what git writes
for those records. The harness checks this on every run and records the
unsorted file's refusal. Sorting the entries in `build_indexrepo` would make
the catalog case valid again. That file is shared, so the change is only
proposed here.

A non-removal entry with the null object ID is refused at final write, before
replacement. An intermediate null-ID record removed later in the same
`--index-info` stream is allowed; mode-0 removal remains a valid no-op for
an absent path. Failed final validation preserves the old index and releases
the command's lock.
