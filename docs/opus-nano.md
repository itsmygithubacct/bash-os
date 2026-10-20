# nano: justify, spell check, word completion and a faster edit path

The `nano` builtin used to answer `^J`, `^T` and `^]` with "not implemented".
They now justify, spell check and complete words. The edit path no longer
re-splits the whole buffer on every keystroke. The marked region is drawn in
reverse video and stays anchored to its text while you edit around it.

```sh
./build.sh --include nano,ts --name nano          # ts is a required companion
out/bash-nano -c 'PATH=; nano notes.txt'
out/bash-nano -c 'PATH=; nano -r 72 -M --speller="aspell list" notes.txt'
```

## Invocation

    nano [-r N | --fill=N] [-M | --trimblanks] [--speller=CMD] [--] [FILE]

`-r`/`--fill` sets the justify width; a value of zero or less is relative to
the terminal width. The default is `-8`, as in GNU nano. `-M` removes the
blanks left at justified line breaks. Unknown options, a malformed width,
`-r` without a value or more than one file exit with status 2. Without a
terminal, nano exits with status 1. Options are reset on every call, so a
setting cannot leak into a later `nano` in the same shell.

## Justify: `^J`, `M-J`

`^J` justifies the paragraph at the cursor, or the next one below it when the
cursor is on a blank line. The cursor then moves to the line after the
paragraph, so repeated `^J` walks the file one paragraph at a time. With the
mark set, `^J` justifies the paragraphs in the marked lines and unsets the
mark. `M-J` justifies the whole buffer. Each justification is a single
piece-table replacement, so one `^Z` (or `M-U`) restores it and `^Y`/`M-E`
re-applies it. A paragraph that is already justified is left alone: it adds
no undo step and does not mark the buffer modified.

The paragraph model and line filling follow GNU nano 8.4:

- A paragraph begins at the first line, after a blank line, where quoting
  changes, or at the first of two lines whose indentation differs. The quote
  prefix uses GNU's default `quotestr`, `^([ \t]*([!#%:;>|}]|//))+`.
- The first line keeps its own quote and indentation. The following lines
  take the second line's.
- Each run of blanks becomes one space. After `.`, `!` or `?` and at most one
  closing bracket, up to two spaces are kept. Trailing blanks are dropped.
- Lines are filled greedily: each line, including its lead, is at most the
  fill width in display columns. CJK characters count as two columns and
  combining sequences as one. A word wider than the fill stays whole on its
  own line.
- The blanks at a break stay at the end of the upper line, as in GNU nano's
  default. `-M` removes them.

`nano selftest-justify` pins 24 cases whose expected text was produced by GNU
nano 8.4 with the same options. `tests/opus-nano-pty.py` replays a subset
through the real keyboard path. It also feeds 24 seeded random multi-paragraph
files to both editors with the same keys (`M-J`, `^S`, `^X`) and options, and
requires the saved files to be byte-identical.

**One intentional difference.** GNU nano measures a paragraph's first line
from the byte offset of the *second* line's lead. When that offset falls
inside a multibyte character, it counts the split bytes as wide invalid
characters and wraps too early. For example, `été sea be a deed end.`
followed by a tab-indented line breaks after `be` at `--fill=12`, although
`été sea be a` is 12 columns wide; `eté sea be a` is not affected. This
builtin measures every line from its own lead. The random oracle starts each
line with an ASCII word, so it only compares inputs where GNU's offset is
harmless, and the selftest pins the difference.

## Spell check: `^T`

The spell checker uses a word-list helper, the interface of `spell(1)`,
`aspell list` and `hunspell -l`. The helper reads text on standard input and
prints the misspelled words, one per line. The command comes from
`--speller=CMD`, otherwise the exported `NANO_SPELLER` variable, otherwise
`spell`. Running it is subject to these limits:

- The command is split on blanks and started with `execvp`, never through a
  shell, so quoting and expansion do not apply.
- The helper receives the marked region, or the whole buffer, on a pipe.
  Its standard error goes to `/dev/null`, so it never sees the terminal.
  It gets the shell's exported variables, like any command bash runs.
- Output is capped at 1 MiB and 4,096 distinct words of at most 255 bytes.
  Carriage returns and blank lines are ignored, and duplicates are dropped.
- The helper has 10 seconds in total, including the wait after it closes its
  output. When that expires it is killed with SIGKILL; no other process is
  signalled.
- A nonzero exit, death by signal, exec failure (`not found`/`cannot run`),
  timeout or oversized output leaves the buffer untouched. The status line
  says which of these happened.
- While the helper runs, SIGCHLD is blocked so Bash's reaper cannot take its
  status, and SIGPIPE is ignored so a helper that stops reading cannot kill
  the shell. Both are restored afterwards, and the pipes are close-on-exec.

For each word, in the helper's order, the cursor moves to its first
whole-word occurrence. A prompt, `Edit a replacement:`, opens prefilled with
the word:

- Backspace removes one grapheme cluster.
- Enter with a changed word replaces every whole-word occurrence in the
  checked text as one undoable edit, so `tehran` is not touched by `teh`.
- Enter with the word unchanged skips it.
- Esc, or end of input, stops the check.

The cursor then returns to its original place, shifted by any edits, and the
status reports `Finished checking spelling (N replaced)` or `Spell check
cancelled (N replaced)`. When checking a marked region, the mark stays set.

## Word completion: `^]`

The fragment is the run of word bytes ending at the cursor: ASCII letters,
digits, `_` and any byte of a UTF-8 sequence, so `ü` completes to `über`.
Candidates are the distinct longer words in the buffer that start with the
fragment, in buffer order from the top, excluding the word being typed.

Each `^]` replaces the inserted tail with the next candidate. After the last
one, the bare fragment returns with "No further matches", and the next `^]`
starts over. This is GNU nano's order and cycle. GNU nano 8.4 also skipped a
candidate only one character longer than the fragment in one probe (`ape`
for `ap`); this builtin offers every longer word. Typing or moving between
presses starts a new completion, and each step is one undo entry. The list
is built once per completion and capped at 1,024 words.

## Selection

`M-A` sets the mark. The region between the mark and the cursor is drawn in
reverse video, on top of any syntax colour, with whole grapheme clusters.
The mark is anchored in the text, not on the screen:

- An edit before it shifts it, and an edit spanning it collapses it to the
  edit's start.
- Undo and redo map it back and forward through the recorded edit span.

Completion and spell checking keep the mark set. Marked justify and cut
unset it, as before.

## Edit path

Every edit used to flatten the whole piece table and rebuild every line
object. A keystroke in an 8 MiB file therefore copied 8 MiB and made about
140,000 allocations. Now:

- The render-line cache is patched in place: only the lines the edit
  touches are rebuilt. Later lines' start offsets are shifted lazily: one
  pending delta applies from a marker line onwards, and an edit only fixes up
  the lines between its own position and the previous edit's.
  `nano selftest-linecache` checks it against a full re-split after each of
  2,000 seeded random edits and undos.
- A split piece's newline count comes from the smaller side, so deleting at
  the edge of an 8 MiB piece no longer rescans it. Counting uses `memchr`.
- Like GNU nano, no frame is drawn while more input is already waiting, so a
  pasted burst is drawn once at the end. Prompts still draw on every key.
- A typed run extends the piece holding the latest append instead of adding
  a piece per key, which keeps undo snapshots small. Snapshots copy piece
  lengths and the add buffer is append-only, so earlier states are
  unaffected.
- Cursor placement from an offset uses binary search over line starts.
- The vertical scroll clamp no longer walks every line when soft wrap is off.
- `^S` no longer rebuilds the line cache after writing, since saving changes
  no text.

Undo and redo still rebuild the cache from the restored snapshot.

## Other fixes

- Backspace in a prompt used to remove one byte, which could leave half a
  UTF-8 character. It now removes one cluster.
- A prompt whose input ended (for example on terminal hangup) used to spin
  forever. It now cancels.
- The mark stayed set from one `nano` call to the next in the same shell.
  It is now cleared.

## Tests

| command | what it covers |
|---|---|
| `nano selftest-justify` | 24 GNU-derived cases plus default/relative fill, cursor placement, repeated ^J, M-J, marked justify, undo/redo, no-op, blank buffer and the first-line-offset difference |
| `nano selftest-spell` | replacement, cancel, skip, end of input, UTF-8 prompt editing, marked region, CRLF/duplicate output, a helper that never reads 200 KiB of input, and the failure paths: exit 3, SIGKILL, hang, close-and-linger, more than 1 MiB of output, missing, not executable, blank command. Also checks no unreaped child, no descriptor leak, and SIGCHLD mask and SIGPIPE disposition restored |
| `nano selftest-complete` | order, cycling, wrap to the fragment, restart, duplicates, own-word exclusion, no fragment, UTF-8, undo, mark kept |
| `nano selftest-selection` | grapheme stepping over emoji+modifier, combining sequences and CJK; cluster backspace; reverse-video render of exactly the marked clusters; mark anchoring across edits and undo; vertical snapping |
| `nano selftest-linecache` | incremental cache vs full re-split, undo to origin, typed-run coalescing |
| `nano selftest-keybindings` | ^J/^T/^] now assert real edits (previously "not implemented") |
| `tests/opus-nano-pty.py BINARY` | the above through a private PTY with an empty PATH: justify vs GNU (fixed and 24 random), undo/redo, spell (replace/cancel/skip/env/override/failure/missing helper), shell descriptor count, completion, UTF-8 movement and visible selection, atomic save mode and no residue, ^O prompt, ^X guard, termios restored exactly (`stty -g`), alternate screen, repeated calls, invalid invocations |
| `tests/opus-nano-sanitize.sh BINARY` | all nano selftests and the PTY suite with nano and ts built under ASan/UBSan |

The existing selftests (`selftest`, `-piecetable`, `-saveprompt`, `-replace`,
`-search`, `-resize`, `-statusbar`, `-yank-ring`, `-atomic-save`,
`-undo-redo`) are unchanged and pass.

## Measurements

Measured 2026-10-19 with `bench/opus-nano.py` on an Intel i7-9850H running Linux
6.12.111+deb13-amd64, through the campaign's bench gate. The editor and the
harness driver were both pinned to CPU 11, the only CPU the gate allowed. Fixtures
were on an ext2/3/4 filesystem, so the saves' `fdatasync` reached the disk. Each
cell is the median of 7 timed sessions after one warm-up, with the minimum and
maximum in brackets. A session runs from `pty.fork` to shell exit, so it includes
starting the shell. On every pass the saved file must hash to a value computed by
the harness independently of either editor, and the exit status must be 0; all 27
cases passed on every pass. The raw report records each sample, both binaries'
SHA-256 and the fixture hashes.

- before: the starting commit `5a91c6e`, `./build.sh --include nano,ts`, binary
  `da8f1b8aeb5123b6…`
- after: this change, same build command, binary
  `93402565896da5f3…`
- GNU nano: `GNU nano, version 8.4`, started by the same bash-os shell with
  `--ignorercfiles`. It receives the same keys and must write the same bytes, but
  it draws the screen differently, so its column is a reference for the same
  edit, not for the same work inside the editor.

| workload | buffer | lines | before (ms) | after (ms) | GNU nano 8.4 (ms) |
|---|---|---|---|---|---|
| open-exit | 16 KiB | 261 | 2.6 (2.4–2.9) | 2.7 (2.6–3.2) | 4.3 (4.2–5.9) |
| open-exit | 1 MiB | 16,645 | 11.4 (11.0–13.9) | 10.5 (9.3–11.6) | 24.9 (20.4–26.6) |
| open-exit | 8 MiB | 133,153 | 53.1 (50.9–54.7) | 50.6 (46.6–51.3) | 92.8 (81.5–108.5) |
| save | 16 KiB | 261 | 5.1 (4.6–5.3) | 4.5 (4.3–4.8) | 5.8 (5.4–6.6) |
| save | 1 MiB | 16,645 | 28.1 (22.2–33.1) | 13.7 (12.8–16.2) | 24.1 (22.3–28.2) |
| save | 8 MiB | 133,153 | 109.2 (98.5–117.5) | 57.8 (51.6–61.0) | 160.7 (150.5–248.4) |
| edit | 16 KiB | 261 | 121.5 (111.0–129.1) | 14.2 (13.7–14.6) | 11.7 (10.7–14.0) |
| edit | 1 MiB | 16,645 | 1315.0 (1273.7–1396.2) | 24.2 (18.7–27.2) | 30.3 (25.5–31.4) |
| edit | 8 MiB | 133,153 | 10412.9 (10160.7–10654.2) | 76.3 (69.6–77.0) | 150.1 (142.4–158.1) |

The `edit` workload: go to the middle line with `^_`, type 400 bytes, delete 100
with Backspace, type ten Enter+`line` pairs (550 editing keys), save, quit. It is
the case the old edit path could not handle: 10.4 s at 8 MiB became 76 ms. Subtracting
the `save` row, the editing part is about 10 ms at 16 KiB and 18 ms at 8 MiB.
What still grows with the buffer is the line-array move on each Enter (ten of
them here). Three causes were found in turn,
remeasuring after each:

1. A full flatten and re-split of the buffer per key (`bench-1`: 18.9 s → 0.95 s
   at 8 MiB).
2. Rewriting every later line's start offset per key, and drawing a frame per
   key during a burst (`bench-2`: 0.61 s; 16 KiB from 83 ms to 18 ms).
3. Recounting the newlines of the untouched half of the original piece on every
   Backspace (`bench-final`: 76 ms).

Host load differed between those runs (the baseline itself measured 16.5 s in
`bench-2` and 10.4 s in the final run), so only rows from the same report are
compared here.

`open-exit` and `save` were not changed beyond dropping the post-save line-cache
rebuild; load still reads the whole file and builds every line object once.

The catalog's existing `nano selftest` case was re-run with the unchanged
`bench/loadables.py --only nano --runs 7 --cpu 11` on both binaries. That case
measures `nano selftest` itself, not editing, and its pass status was `ok`
for both: 66.6 ms before and 61.3 ms after (medians, self-timed, no external
ratio). It does not cover the new code paths; the session table above does.
