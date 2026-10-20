# vi deletion completion and independent validation

This follow-up starts at `8b52898`, after the integrated cursor clamp,
newline-count optimization and visual UTF-8 correction. It preserves the
predecessor's [report and historical measurements](opus-vi.md). The original
`G` followed by repeated `dd` defect is fixed there; independent testing and
review found additional cursor/deletion edge cases and an error-status defect.

For input `a\n\nb` without a final newline, the first `Gdd` writes `a\n` but
must leave two logical lines in memory: `a` and an empty unterminated line.
Previously the next `dd` deleted `a`, producing zero bytes. It now deletes the
empty line and leaves `a`, matching nvim with `nofixeol`.

The piece table and undo snapshots now retain an `empty_last_line` flag.
Deletion, line counts, cursor clamping, rendering, motion and linewise
yank/put respect that state. An intermediate save retains it in memory;
reopening the serialized bytes uses the ordinary file interpretation.
Insertion into that line consumes the flag when it becomes nonempty. Deleting
all logical lines reaches the defined zero-byte buffer, where further `dd`
does nothing. No extra newline is written to encode internal state.
Forward word motion at EOF now stays on the last character, so `Gddwx`
edits that character instead of silently leaving the buffer unchanged after
the delete.

In `--keys` mode, `:q!` and successful `:wq` also preserve an earlier command
failure in the return status. Previously they reset a failed save to success.
The mmap backing, piece storage, shorter-side newline counting, and
temporary-file/write/fdatasync/rename save implementation remain intact.
No common helper or companion loadable changed; the vi-only build stages
the existing `_bl_key` helper through `config/helpers.json`, plus the
build system's unconditional `_jsmn` helper.

## Validation

`tests/sol-vi-delete.py` supplies an independent Python line-list oracle,
checks all remaining bytes through both `--keys` and ex scripts, and compares
the results with nvim. Its matrix covers empty and one-line inputs, UTF-8 and
binary data, blank lines, missing/present final newlines, and deletion past
the empty state. The 250-delete assertions include blank lines and no final
newline, so skipped or extra deletes fail. Another case edits 28 locations
before deleting 250 lines, exercising many original/add piece boundaries.
Saving over the mapped input and continuing to delete is checked separately.

Private-directory rename failures and child-only file-size limits exercise
cleanup after temp-file creation and partial writes. Tests assert original
bytes, absence of leaked temporary files, stable descriptor counts across
20 repeated failure pairs, native dispatch with an empty PATH, and successful
use after failures in the same shell.

`tests/opus-vi-dd.py` retains its previous assertions and adds interactive
nvim comparisons for the new line state through counts, motions, undo/redo,
yank/put and ex commands. Its private PTY reference avoids nvim's startup
undo-block merging. The new headless reference cases deliberately contain
no undo operations. `tests/opus-vi-sanitize.sh` runs both suites against the
production loadable with ASan/UBSan; LSan covers the internal selftest.
The final native and sanitizer runs each passed 25 internal checks,
151 predecessor-suite checks and 180 new-suite checks: 356 reported checks,
including 223 nvim comparisons, with zero skips. All three newly found
defects were first reproduced against the inherited binary in saved logs.

The coverage is the shipped editor subset, not full vi conformance. Existing
deferred features in `loadables/vi.c` remain deferred. The existing documented
empty-buffer insertion convention and other deliberately unpaired cases in
the predecessor suite remain explicit. No physical terminal or hardware is
required for the deletion contract.

## Measurements

The command-specific `bench/opus-vi.py` now also measures
`vi-gdd-noeol`: 250 actual last-line deletes on 1,000 lines containing blank
lines, with no final newline. Each warm-up and timed pass writes a separate
file, whose complete bytes must match the independently computed 750-line
prefix. The inherited implementation fails this case and receives no timing.

The ordinary 43,000-byte `vi-gdd`, 1,680,000-byte `vi-gdd-large`, and unchanged
full-save `vi-write` work units are retained. The small fixture's actual
size is 43,000 bytes; the predecessor prose called it 45,000. Fixture hashes
and the 32,250-byte remaining prefix define the unchanged work.

The optional provenance manifest binds each binary hash to its own source
hash and commit, rather than attributing the current working tree to every
binary in a paired run. Raw reports and command logs belong in the task
evidence directory, outside version control.

Final paired report: `reports/final-paired.json`. Intel i7-9850H,
Linux 6.12.111, GCC 14.2, Bash 5.3.15, nvim 0.10.4, pinned to CPU 11.
Each implementation uses 10 passes per batch, a validated warm-up, then
nine timed batches with rotating/interleaved implementation order. The source
commit is `1f916b0`; the only uncommitted file was this documentation.
All final-binary and nvim case statuses are `ok`.

| Workload | Inherited ms/pass | Final ms/pass | nvim ms/pass |
|---|---:|---:|---:|
| 43 KB, G + 250 dd + save 32,250 B | 2.81 | 2.71 | 18.67 |
| No EOL/blank lines, G + 250 dd + save 7,949 B | rejected (7,937 B) | 2.18 | 15.08 |
| 1.68 MB, G + 250 dd + save 1,676,500 B | 8.95 | 9.07 | 40.51 |
| Full 1.68 MB save, no edits | 8.87 | 8.91 | 35.26 |

Final per-pass sample ranges are respectively 2.48–3.12, 2.14–2.51,
8.58–10.82 and 8.33–11.61 ms; the report retains every batch sample.
Ordinary deletion and save ranges overlap the inherited implementation.
The earlier full-file rescan bottleneck was not reproduced, so no additional
performance optimization was warranted and no speedup is claimed.
These are whole-command workloads: nvim starts one external process per
pass, whereas builtin invocations share a shell. They are not editing-engine
speed ratios. The corrected missing-EOL case has no valid inherited timing.

Historical numbers remain historical: the reviewed full-save batch was
72.15 ms for 19 passes, versus 364.084 ms externally. The predecessor recorded
2.38 ms/pass for the small deletion workload, 7.31 ms/pass for the large one,
and 6.49 ms/pass for full save. These are not paired with this follow-up's
measurements. The original broken tail-deletion workload performed one edit
and 249 no-ops and cannot support a speedup claim.
