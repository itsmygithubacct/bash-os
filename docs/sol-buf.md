# Buffer persistence, failure contracts and measured costs

The buffer now builds a replacement independently on reload and commits it only
after all reads and allocations succeed. A failed reload retains contents,
filename, trailing-newline policy and dirty state. Successful replacement releases
the old heap lines, sparse checkpoints and mapping through the normal destructor.

Atomic save uses the same raw writer as `text`: one mapped span for an unedited
buffer, or a 64 KiB scratch buffer for edited/streamed lines. It still writes a
sibling temporary file, preserves mode, synchronizes data, renames, and attempts
to synchronize the parent directory. Allocation, data-write, data-sync and close
failures before rename do not publish the temporary file or change the retained
name/dirty state. The prospective filename is allocated before writing; saving
through the buffer's own retained name keeps that allocation alive. Parent
sync remains best effort, as before; these tests do not qualify power-loss
behavior on physical storage.

Numbers now reject empty strings, trailing junk and overflow; file descriptors
also have to fit an `int`. Text/line/count output reports failed stdio flushes and
clears the stream error for later calls. Failed handle publication releases the
slot, including readonly-variable and output failures. `set-name` preserves its
previous name on allocation failure. The journal formatter now sizes `I`/`D`
records with the correct variadic arguments, preventing truncated hex payloads.

The 32-slot integer handle ABI is unchanged. A freed slot rejects operations
until reallocated; a saved integer can then refer to the new occupant. There are
no generation identifiers. No shared piece-table helpers, `clip.c`, or `nano.c`
were changed. `undo` and `clip` still use the existing public buffer API.

## Verification

`tests/sol-buf-check.py BINARY` performs 44 checks with an empty command PATH:

- Regular-file mappings and streamed input preserve empty files, blank lines,
  NUL/high bytes, CRLF and unterminated final lines exactly.
- Range output crosses 1,024-line checkpoints and 65,536-byte boundaries;
  zero-length and clipped ranges preserve the established separator rules.
- A seeded 160-edit sequence is checked after every operation against an
  independent Python byte-array model.
- One hundred load/edit/reload/retained-name-save cycles preserve exact contents
  and FD counts; another fifty cycles verify mapping counts after successful and
  failed loads and after free.
- Freed slots, table exhaustion/reuse, invalid numbers, output failures, failed
  handle binding, undo/clip binary transit and all four journal record shapes are
  asserted. Atomic replacement retains an old open reader/hardlink and file mode.

`tests/sol-buf-faults.py BINARY` performs 47 checks with the task's probe loaded.
The probe includes the genuine production source and intercepts only its local
allocation, read, write, mmap and data-sync calls. Tests fail selected allocation
sites, reads after partial input, a second output write after a temporary file
already contains bytes, zero writes and data-sync. They also exercise short
writes/EINTR and verify insertion and set-name allocation rollback. Fault cases
check status, FD counts and independent byte oracles; an unexpected success fails the
suite explicitly.

Both suites pass natively and with ASan/UBSan instrumentation of buf/undo/clip.
The original `tests/vt-buf-edges.py` also passes (four checks). LeakSanitizer is
disabled for the hosting Bash; mapping/FD assertions and ASan/UBSan cover the
stated cleanup/access scope. Full terminal UI interaction and the global suite
are left to integration. The build selection is `buf,undo,clip,vt,cat`;
`config/helpers.json` supplies buf dependencies for undo/clip and libgrapheme for
vt. The buffer/undo/clip checks from terminal smoke are covered by the dedicated
suite without building unrelated terminal commands.

These are scoped software contracts, not complete conformance claims. Existing
journal-write failure semantics still apply the edit before reporting failure;
there is no transaction spanning an external journal. External concurrent
truncation of a mapped source and physical crash/power-loss qualification are
outside this work.

## Measurements

The historical 3.13× `buf-text` slowdown did not reproduce on the starting build.
The initial unchanged shared harness measured 19 calls at 3.251 ms versus external
cat at 18.252 ms, with both repeated outputs validated in its separate preflight
batch. Those compatibility-harness timings are supplementary: the dedicated
`bench/sol-buf-text.py` adapter uses the identical catalog fixture and checks every
output byte of every timed batch and warmup. The starting source
already emitted an unedited mapped buffer directly; no speculative text rewrite
was needed.

Task-owned `bench/sol-buf.py` measures 423,000-byte, 4 MiB and 32 MiB binary-text
fixtures. Every case has one discarded warmup and seven measured batches pinned
to CPU 11. Every operation's output file is compared byte-for-byte with the
independent Python fixture, including the warmup; every shell command must
succeed. Fixtures and destinations are reset identically. Reports record fixture,
source, binary and launcher hashes, versions, sample distributions, work counts,
and shell peak RSS. `tests/sol-buf-rusage.c` forks from a small freshly executed
launcher so Python's inherited RSS does not contaminate the shell measurement.
Timings include launcher/shell startup and setup and are API timings without an
external ratio.

Each batch creates and frees one handle and performs one setup load. Text cases
perform 19 text operations (22 API calls total); edited text adds two setup edits
(24 calls). Reload cases perform seven loads and seven validating text operations
(17 calls). Save cases perform two saves (five calls), or seven calls including
two setup edits. The input-byte field is fixture size; loaded bytes and emitted
bytes are recorded separately.

| API batch | Input bytes | Before ms | Final ms | Before peak KiB | Final peak KiB |
|---|---:|---:|---:|---:|---:|
| 19 × text | 423,000 | 4.301 | 6.811 | 3,732 | 3,800 |
| 19 × edited-text | 423,000 | 5.922 | 7.225 | 4,032 | 4,072 |
| 7 × load | 423,000 | 6.047 | 5.153 | 3,780 | 4,228 |
| 2 × save | 423,000 | 17.842 | 6.082 | 3,824 | 3,752 |
| 2 × edited-save | 423,000 | 18.804 | 6.584 | 4,064 | 3,992 |
| 19 × text | 4,194,304 | 39.391 | 39.607 | 7,500 | 7,524 |
| 19 × edited-text | 4,194,304 | 57.397 | 59.328 | 9,640 | 9,684 |
| 7 × load | 4,194,304 | 50.657 | 36.239 | 7,496 | 11,636 |
| 2 × save | 4,194,304 | 166.726 | 14.442 | 7,500 | 7,516 |
| 2 × edited-save | 4,194,304 | 162.877 | 19.176 | 9,548 | 9,620 |
| 19 × text | 33,554,432 | 309.951 | 293.905 | 36,148 | 36,196 |
| 19 × edited-text | 33,554,432 | 447.729 | 436.498 | 52,768 | 52,724 |
| 7 × load | 33,554,432 | 373.782 | 272.843 | 36,188 | 68,912 |
| 2 × save | 33,554,432 | 1226.655 | 78.081 | 36,156 | 36,168 |
| 2 × edited-save | 33,554,432 | 1240.883 | 125.306 | 52,588 | 52,632 |

Values are batch medians; memory is the maximum shell peak RSS across the seven
samples. The source/binary builds ran on the same host and CPU, with identical
fixtures and reset rules. They are sequential batches under the campaign gate,
not exclusive-host microbenchmarks. The complete sample distributions and hashes
are in `scale-before-v3.json` and `scale-final.json` in the task receipt.

The 423,000-byte scale text batch increased from 4.301 to 6.811 ms; no general
text speedup is claimed. The separate interleaved catalog-fixture check below
was stable. The largest save improvement corresponds to the demonstrated write
count reduction. Reload rollback retains the old buffer until commit: the 32 MiB
reload batch's peak RSS increased from 36,188 to 68,912 KiB. This is mapped-page
RSS, not a measurement of unique physical memory or anonymous heap alone.

On the exact catalog text fixture, the stricter timed-output adapter measured
19 text calls at 7.357 ms before and
7.045 ms after, versus 21.131 ms
for external cat (final/cat = 0.333). All 8,037,000
output bytes matched in every batch, including warmup. This adapter includes
file output and startup/setup; its timings are distinct from the supplementary
shared harness's `/dev/null` measurements. See `text-validated.json`.


`bench/sol-buf-profile.py` counts source-local allocation requests, explicit
`memcpy` bytes and raw writes in the same production implementation, separately
from timing. Allocation request bytes are not live heap/peak memory, and explicit
copies exclude internal realloc/memmove copying. The baseline 4 MiB short-line
save issued 524,288 writes; the mapped text path used one write, zero allocations
and zero copies. First edit costs remain visible: realizing a sparse line index
and copying the edited line is unchanged. Rollback now keeps the old buffer alive
while loading its replacement; peak RSS for repeated reload can consequently
increase, even though the sparse index remains small.

| 4 MiB short-line operation | Allocations before → final | Explicit copy bytes before → final | Writes before → final |
|---|---:|---:|---:|
| text | 0 → 0 | 0 → 0 | 1 → 1 |
| save | 1 → 2 | 206 → 323 | 524,288 → 1 |
| edited-text | 0 → 0 | 3,932,160 → 3,932,160 | 64 → 64 |
| edited-save | 1 → 2 | 206 → 3,932,483 | 524,288 → 64 |

The additional save allocations hold only pathnames. Mapped save copies only
pathname bytes, not payload bytes. Edited save trades bounded payload copying
for batched writes; it does not allocate a joined whole-buffer string. The first-edit
allocation/index costs were profiled but left unchanged. The original exploratory
`scale-before.json` is retained but superseded: its RSS inherited Python's peak,
and its source hash came from the changing working file. The attempted v2 run
failed because `/usr/bin/time` was absent. Only v3 and final RSS enter this table.

All builds and measurements must use the campaign's build/bench resource gates.
Build probe binaries separately with `bash tests/sol-buf-build-probe.sh OUTPUT`.
For instrumentation, set `BUF_LOAD_ENV=OUTPUT/probe.sh` for the Python suites.
For sanitizers, set `BUF_LOAD_ENV=OUTPUT/sanitize.sh` and `BUF_ASAN_LIB` to the
runtime path listed in `OUTPUT/asan-runtime.txt`; the tests apply those settings
to the child shell only. Run the scale benchmark
with `--binary BINARY --source SOURCE --rusage OUTPUT/rusage --cpu 11 --output
REPORT.json`; use the same fixture/options for both builds. Preserve raw reports
outside Git and register tests/catalog evidence through integration metadata.
