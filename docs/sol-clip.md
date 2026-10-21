# clip: atomic edits, ring order and measured copy costs

`clip` keeps a 16-slot yank ring per handle and cuts, copies and pastes
between it and `buf` handles. This note records the contract the command now
keeps, what changed to get there, and how it was checked and measured.

## Contract

- **All or nothing.** A cut, copy or paste either completes or leaves the
  buffer bytes, the buffer's dirty flag, every ring slot and the active pointer
  exactly as they were, allocation failure included. An entry is built off to
  the side and published only after the buffer edit has succeeded. Buffer edits
  are ordered so that only the first step can fail: a multi-line byte cut first
  appends the last line's suffix to the first line, after which the remaining
  deletions cannot fail; a column paste inserts the new lines in one
  all-or-nothing call, then splices the first piece into the source line.
  Previously a failed allocation had already advanced the ring and emptied a
  slot, and a failed paste left part of the paste behind.
- **Ring order.** The ring fills slots 0–15 in order. Once full, a new entry
  replaces the oldest one. It used to replace the slot after the *active*
  pointer, so after `yank-prev` a cut discarded a recent entry and kept older
  ones. `yank-prev` and `yank-next` wrap between oldest and newest. `text -N`
  addresses physical slots; a slot never used fails with status 1.
- **Entries and regions.** A line range records one piece per line. A byte
  range `[FL:FC, TL:TC)` records one piece per buffer line it touches. `text`
  writes each piece followed by `\n`; `text -X` hex-encodes the pieces joined by
  `\n`. `copy-range H B I I` records an entry with no pieces, and a zero-length
  byte range records one empty piece. Pasting no pieces changes nothing.
  Pasting one empty piece at a column changes nothing. Pasting it as lines
  inserts one empty line. Neither a zero-length cut nor an empty paste marks the
  buffer dirty. `END` beyond the line count is clipped; `START` must name a line.
- **Bytes.** Columns are byte offsets, as in `buf`. A range may split a UTF-8
  sequence, a combining sequence or a ZWJ cluster; the bytes still move exactly,
  so pasting a cut back at the same place restores the original. NUL, CR,
  high bytes and embedded `\n` bytes inside a line round-trip.
- **Handles.** Handles follow `buf`'s number rules: nonnegative decimal with no
  empty string, trailing junk or overflow, so `""` no longer selects handle 0.
  A freed clip or buf handle is rejected, with status 2, until the slot is
  reallocated. Integers are reused, as in `buf`, with no generation number.
  Entries are copies, so freeing or reloading the source buffer does not affect
  them. `new` reports output failures and readonly-variable failures, and
  releases the handle when it cannot publish it.
- **Arguments.** Every verb rejects missing and extra arguments with status 2.
  `paste` on an empty ring and `yank-*` on an empty ring return 1. Output
  failures from `text`, `text -X` and `text -F` return 1 with a message.

## Shared buf helpers

`buf.c` gained four functions in its public C API, in commits of their own.
All of them are additive and change no existing behaviour.

| Function | Purpose |
|---|---|
| `bb_pub_get_lines` | Resolve a run of lines in one sequential walk. Repeated `bb_pub_get_line` rescans from a 1,024-line checkpoint for every line of an unedited (paged) buffer. |
| `bb_pub_insert_lines` | Insert a run of lines with one shift of the record array, all or nothing. |
| `bb_pub_delete_lines` | Remove a run of lines with one shift. Fails only on a bad range or when realizing a paged buffer fails, leaving it unchanged. |
| `bb_pub_dirty` | Read the dirty flag, so a rolled-back paste can restore it. |

The existing `buf` suites pass unchanged against the new source.

## Verification

`tests/sol-clip-check.py BINARY` runs 17 scripted checks with an empty `PATH`.
Each script runs in one shell and requires an unchanged FD table at exit. An
independent Python model of the buffer and the ring supplies the expected bytes.

- Line and byte verbs, including UTF-8 splits inside a 2-byte and a 4-byte
  sequence, a combining mark and a ZWJ cluster, with byte-exact restore.
- Ring wraparound in both directions, replacement of the oldest entry after
  rotation, and every physical slot after wraparound.
- Empty ring, empty regions, empty buffers and cleared entries, including the
  dirty flag.
- Stale clip and buf handles: freed, malformed, out of range and reused. An
  entry survives `buf free` and `buf load` of its source.
- Invalid input for every verb, with no change to buffer or ring.
- Output failures to `/dev/full` and a closed FD, a failed binding and
  handle-table exhaustion.
- A 9,000-line binary fixture with a 1 MiB line. Its paged copies start past
  the first and second checkpoints and end on the final line.
- A seeded 500-step sequence of every verb, compared after each step: status,
  line count, buffer bytes, dirty flag and active entry, then every slot.

`tests/sol-clip-faults.py BINARY` loads `tests/sol-clip-probe.c`: the genuine
`buf.c` and `clip.c` compiled into one module whose allocation calls can fail
on request. For each of 39 operations it fails allocation 1, 2, … until the
operation succeeds. The operations cover every cut, copy and paste form on
paged and realized buffers, pastes of 1–3 pieces, record-array growth and a
full ring; a separate check fails `new`'s allocation. Each injected failure must return nonzero with the full snapshot
unchanged. The final success must equal an explicitly listed state.

Build the probe modules with `tests/sol-clip-build-probe.sh OUT [CLIP_SOURCE
[BUF_SOURCE]]` through the build gate. `CLIP_LOAD_ENV=OUT/probe.sh` selects the
counters and faults. `OUT/sanitize.sh` (fault suite) or `OUT/plain.sh`
(functional suite), with `CLIP_ASAN_LIB` set to the path in
`OUT/asan-runtime.txt`, runs the same suites under ASan/UBSan. LeakSanitizer is
disabled for the hosting Bash.

## Measurements

All timings were taken on one host (i7-9850H, CPU 11 pinned), through the
campaign's bench gate, while other campaign work kept the host loaded. Values
are medians of seven samples after one discarded warmup. The baseline is the
starting commit's `clip.c`/`buf.c`; the final binary is built from this
branch. The baseline was built with `--include buf,clip,cat`, the final with
`--include buf,undo,clip,vt,cat` (the extra builtins serve the buf regression
suites).

### The historical 1.47× `clip-text` ratio

The catalog case times `clip text 0` on a 4,000-line entry against
`head -n 4000 text`. Both write the same 209,906 bytes, and the harness checks
them on every pass. The work is not the same: `head` is forked, executed and
reads the file on each pass, while `clip` writes from memory. On the unchanged
shared harness the starting binary measured 11.358 ms for 57 passes against
114.43 ms for `head` (0.099×). The historical 1.47× (2026-09-12 build) does not
reproduce. The final binary measured 6.093 ms for 66 passes against 98.0 ms
(0.062×). These two harness runs were calibrated separately and ran at
different times, so they are not a paired comparison; the interleaved adapter
below is.

### Region sizes

`bench/sol-clip.py` interleaves baseline and final batches. Each batch is a fresh
shell: untimed setup, then a timed loop (`$EPOCHREALTIME` inside the shell, so
process start and setup are excluded), then untimed validation. Every pass must
succeed. Its output, or its effect on the buffer, is compared byte for byte with
an oracle built from the fixture, for the warmup and every sample. `text` is the
catalog fixture (423,000 bytes, 8,062 lines, no final newline, generated exactly
as `bench/loadables.py` does); `large` has 65,536 lines with UTF-8 words;
`oneline` is one 4 MiB line. `head -n K` is the matched reference only where its
bytes are identical; at 8,062 lines and above the fixture's last line has no
newline, `head` emits one byte fewer, and those cases are self timings.

| Workload (batch) | Region | Baseline ms | Final ms | head ms |
|---|---:|---:|---:|---:|
| 64 × text | 1 line, 55 B | 0.522 | 0.502 | 86.203 |
| 64 × text | 100 lines, 5,217 B | 0.922 | 0.905 | 97.376 |
| 19 × text | 4,000 lines, 209,906 B | 3.241 | 2.454 | 34.125 |
| 19 × text | 8,062 lines, 423,001 B | 7.462 | 5.734 | — |
| 7 × text | 65,536 lines, 2,445,130 B | 20.347 | 11.263 | — |
| 7 × text | 1 line, 4 MiB | 19.683 | 20.218 | — |
| 16 × copy-range, paged | 100 lines | 1.707 | 0.277 | — |
| 16 × copy-range, paged | 4,000 lines | 489.360 | 4.153 | — |
| 16 × copy-range, paged | 8,062 lines | 1101.945 | 10.419 | — |
| 16 × copy-range, paged | 65,536 lines | 8150.800 | 81.688 | — |
| 16 × copy-range, realized | 4,000 lines | 12.949 | 3.288 | — |
| 16 × copy-range, realized | 65,536 lines | 194.854 | 60.301 | — |
| 7 × paste appended | 4,000 lines | 3.846 | 3.561 | — |
| 7 × paste appended | 65,536 lines | 74.392 | 63.337 | — |
| 7 × paste at a column, mid-buffer | 100 lines | 8.159 | 0.325 | — |
| 7 × paste at a column, mid-buffer | 4,000 lines | 991.244 | 5.181 | — |
| 7 × paste at a column | 1 line, 4 MiB | 145.321 | 42.571 | — |
| 7 × (cut-range from line 0 + paste back) | 4,000 lines | 403.204 | 6.194 | — |
| 7 × (cut-range from line 0 + paste back) | 65,536 lines | 146.607 | 80.355 | — |

The full 34-case report, with all samples, fixture/binary hashes and tool
versions, is kept with the task evidence. Single-line 4 MiB cases other than the
column paste show no resolved difference (their sample ranges overlap, with
equal minima). Mid-buffer column pastes of 8,062 and 65,536 lines were timed on
the final binary only (6.409 and 69.685 ms for seven pastes). The counts below
put the baseline at about 1 GB and 68.7 GB of record moves per paste for those
two sizes.

### Copies, allocations and writes

`bench/sol-clip-profile.py` runs the same operations through the probe modules
for both revisions and validates each result. Counts cover only buf.c and
clip.c. Allocation request bytes are summed requests, including every
`realloc` step, not live memory. Copies are explicit `memcpy` bytes; moves are
`memmove` bytes.

| Operation | Allocations | Copied bytes | Moved bytes | Writes |
|---|---:|---:|---:|---:|
| text, 4,000 lines | 0 → 0 | 205,906 → 0 | 0 → 0 | 4 → 1 |
| text, 65,536 lines | 0 → 0 | 2,379,594 → 0 | 0 → 0 | 38 → 1 |
| copy-range, 4,000 lines | 12,000 → 3 | 205,906 → 205,906 | 0 → 0 | — |
| copy-range, 65,536 lines | 196,608 → 3 | 2,379,594 → 2,379,594 | 0 → 0 | — |
| paste lines at mid-buffer, 4,000 | 4,001 → 4,001 | 205,906 → 205,906 | 515,968,000 → 128,992 | — |
| paste lines at mid-buffer, 65,536 | 65,536 → 65,536 | 2,379,594 → 2,379,594 | 68,719,476,736 → 1,048,576 | — |
| cut-range of first 4,000 lines | 12,000 → 3 | 205,906 → 205,906 | 519,936,000 → 129,984 | — |

Content bytes are copied once in both revisions, as they must be: the ring
holds copies, and `buf` owns each line's storage. What went away is the
per-line slot allocations and the array growth behind them, the second copy
`text` made into a staging buffer, and the per-line record-array shifts.
Copying from an unedited buffer also no longer rescans its sparse index per
line, which no counter here measures: the paged `copy-range` timings above
show it.

## Limits

These are scoped software contracts, not a full conformance claim. Columns are
byte offsets with no grapheme awareness; splitting a sequence is allowed by
design. The ring lives in process memory and is not shared between shells.
Interactive editor integration (`nano`) does not use `clip` and is not covered
here. The bulk insert still copies every pasted byte into a separate heap line,
which is how `buf` owns line storage.
