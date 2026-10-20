# vi: line deletion, cursor clamping and the G + dd workload

Source: `loadables/vi.c`. Tests: `tests/opus-vi-dd.py`, `tests/opus-vi-sanitize.sh`.
Bench: `bench/opus-vi.py`.

## The defect

`dd` on the buffer's last line left the cursor at the offset just past the
final newline. That offset is not a line, so every later `dd` deleted an empty
range, returned success and pushed an undo step. `G dd dd dd` on `a b c d`
therefore removed one line instead of three. `G` also stopped at the last
*non-empty* line, and `j` on the last line could move onto the same phantom
offset.

The historical benchmark fixture `vikeys` (in `bench/loadables.py`) avoids
`G` before its 200 `dd` for this reason. With `G` the case would have timed one
edit plus 199 no-ops and still passed validation, because a self-referenced
case only compares the builtin with its own first pass.

## Behaviour now

* **One cursor rule.** After any edit, undo, redo or `:N`, the cursor is on a
  real line (`bv_cursor_normalize`). A final newline ends the last line; it
  does not start another one. `"a\n"` has one line, and the empty buffer has
  none.
* **dd** deletes the current line and puts the cursor on the first non-blank
  of the line that followed, or of the new last line. Repeated `dd` keeps
  deleting until the buffer is empty (zero bytes). After that, `dd` does
  nothing and adds no undo step.
* **Final-newline state is kept.** Deleting the last line of a file that has
  no final newline also removes the newline before it, so `a\nb\nc` with `G dd`
  becomes `a\nb`. A linewise put after such a last line supplies the newline
  itself. The register always holds whole lines (`c\n`).
* **Counts:** `[N]h j k l`, `[N]x` (clamped to the line), `[N]dd` and `d[N]d`
  (the two counts multiply), `[N]yy`, `[N]p`/`P`, `[N]u`, `[N]Ctrl-R`, `[N].`
  and `[N]G`. A count larger than the lines left below is clamped. A count
  above one on the last line fails and changes nothing, as in vi.
* **G** goes to the last line (trailing empty lines count), and `[N]G` goes to
  line N. Both land on the first non-blank.
* **Undo/redo restore the cursor** saved with each snapshot, then clamp it.
* **Ex:** `:[range]d[elete] [count]` with addresses `N`, `.`, `$`, `%`, and
  `+N`/`-N` offsets. Also `:$`, `:u[ndo]` and `:red[o]`. Invalid ranges are
  errors: `E16` out of range, `E493` backwards, `E939` zero count, `E488`
  trailing text and `E481` for a range on another command. Each sets exit
  status 1 and changes nothing. More than 16 `-c` commands is now a usage
  error (exit 2); before, the extra commands were dropped silently.
* **UTF-8:** `h`, `l`, `$`, `x` and charwise `p` step over continuation
  bytes, so a multibyte character moves and deletes as a whole. Line
  operations are byte-transparent, including NUL bytes under `-b`.
* **State between calls:** `bv_reset_state` now also clears the pending
  operator and count. A key file ending in `3d` can no longer swallow the
  first key of the next `vi` call in the same shell.
* **ESC** in insert mode stays on the current line. Before, ESC on an empty
  line, or at column 0, moved the cursor back onto the previous line.

The piece table, mmap load, temp-file + `fdatasync` + `rename` save, and the
save error paths are unchanged. Snapshots store one extra cursor field.
`bv_line_to_pos` and `bv_line_number` now skip whole pieces using their cached
newline counts, instead of reading the file one byte at a time through
`bv_byte_at`. Splitting a piece counts newlines on the shorter side
(`bv_piece_nl`).

## Reference comparison

`tests/opus-vi-dd.py` runs 109 checks (97 compared with nvim) through the
production builtin, with an empty PATH. Each written file is checked against
a fixed expected value. When nvim is installed, each case is also typed into
an **interactive nvim on a private PTY**, started with
`-u NONE -i NONE -n -c 'set nofixeol sol'` (plus `-b` for binary cases), and
the written bytes must match.

* `nofixeol`: this vi keeps a missing final newline; nvim's default would add
  one.
* `startofline`: POSIX vi puts the cursor on the first non-blank after `G`
  and linewise deletes. nvim's default keeps the column.
* PTY, not `--headless -s`/`-c`: nvim joins every change made during startup
  into one undo block. Under `-s`, `Gdddddduu` restores all four lines, and
  `:$d` three times followed by `:undo` does the same. Only an interactive
  session syncs undo per command the way vi does.

Cases deliberately not compared, each with the reason in the test:

* typing into the emptied buffer: vi writes `y`, nvim writes `y\n` (nvim keeps
  an end-of-line flag);
* `:3,2d`: nvim prompts to swap the range;
* `:1,2w`: nvim writes those lines, this vi rejects the range with `E481`.

## Measurements

Host: one 12-CPU x86_64 Linux 6.12 machine. Runs are pinned to CPU 5,
use an empty PATH and a warm cache, and each case has a warm-up batch plus
9 timed batches. Implementations are interleaved and rotated per round.
Every pass writes its own `out.N`. Every `out.N` from every batch is checked
against an expected value computed in Python: the first 750 of 1,000 lines
(32,250 B), the first 119,750 of 120,000 `duplicates` lines (1,676,500 B),
or the unchanged 1,680,000 B. Figures are median ms per pass, from
`bench/opus-vi.py` (report `opus-vi-bench-final.json`).

| case | work per pass | baseline 2317322 | da07205 (clamp fix) | 1019105 (final) | nvim 0.10.4 |
|---|---|---|---|---|---|
| vi-gdd | G + 250 actual dd + :w, 45,000 B file | output-mismatch (42,957 B: 1 line deleted) | 21.10 | **2.38** | 14.29 |
| vi-gdd-large | G + 250 actual dd + :w, 1.68 MB file | output-mismatch (1,679,986 B) | 765.98 | **7.31** | 29.84 |
| vi-write | load + full 1.68 MB save, no edit | 6.63 | 6.64 | 6.49 | 23.26 |

* The baseline cannot be timed on G + dd: it deletes one line and then 249
  no-ops, so the harness rejects its output. No speedup is claimed against
  the baseline for this workload.
* The first correct build (da07205) made the deletes real and exposed the
  cost of each one: splitting the 1.68 MB mapped piece recounted the newlines
  of everything kept, and the delete path counted lines twice more.
  1019105 counts the shorter side of a split, subtracts it from the cached
  piece total, and takes the deleted-line count from the yanked text. Same
  bytes, 766 → 7.3 ms per pass.
* The save path is unchanged. vi-write at 6.49 vs 6.63 ms is within noise
  (the sample ranges overlap), so no save speedup is claimed. nvim did
  equivalent work (identical bytes) under `-u NONE -i NONE -n --headless
  -c "set nofixeol sol"`, so the nvim column is a valid comparison.

Historical cases through the unchanged `bench/loadables.py --only vi`
(reports `loadables-vi-base.json` and `loadables-vi-final.json`; same host
and CPU, separate invocations; batch medians):

| case | historical (2026-09-12) | baseline today | final today |
|---|---|---|---|
| vi-write (vs nvim) | 72.15 ms / 19 passes, nvim 364.08 | 80.48 / 10 passes, nvim 295.21 | 73.08 / 10 passes, nvim 257.13 |
| vi-keys (self) | — | 572.95 / 3 passes | 211.82 / 3 passes |

Today's vi-keys output is byte-identical on both binaries (`keysout` sha256
`ec5654ea2e991a2e…`, 117,201 B), so its change is like-for-like. The x and dd
splits there no longer rescan the mapped `left` piece. That fixture still has
no `G`, as the shared harness defines it. The G + dd workload is measured
here instead. The historical 72.15 ms used 19 passes and an older binary;
it is kept as recorded and not paired with today's figures.

Measurement qualification: the nvim column starts an external process for each
pass, including startup, while builtin passes share one shell. These are
end-to-end command workloads, not isolated editing-engine speed ratios.
The recorded measurements precede the visual UTF-8 endpoint correction; they
must not be represented as measurements of the corrected code. Leak detection
covered `vi selftest`; the key/ex regression suite used ASan/UBSan with leak
detection disabled. Visual endpoint regressions now cover two-, three-, and
four-byte UTF-8 characters for deletion and yank/put, in both directions.
