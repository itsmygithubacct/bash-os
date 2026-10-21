# tac: bounded GNU regex separators and GNU window parity

This follow-up to the [bounded-input work](sol-tac.md) replaces the
whole-file regex fallback with a matcher whose memory does not depend on
input or record size. It also emulates GNU tac's regex read windows and
records five GNU tac 9.7 defects that the builtin deliberately does not
reproduce. It fixes a literal-separator read regression. Literal match
rules, pipe spools, output buffering and descriptor ownership are
unchanged.

## Regex windows

GNU tac searches a `-r` separator in a window aligned on the file: 8192
bytes at first, doubled while the unprinted record is longer than the
window, with the size carried over to later files. Each `re_search` covers
the window up to the previous match start. When a search fails, the window
widens to the left, and the whole pending record is searched again. Anchors
are relative to that buffer: `^` and `` \` `` hold at the window base, and
`$`, `\'` and `\>` hold at the previous match start. For example,
`tac -r -s 'A\>'` splits a run of `A`s into one-byte records.

The builtin runs the same loop for every regex separator. Before this change,
a `-r` separator without metacharacters used the literal scanner. Its overlap
behavior at window bases differs from GNU's regex search. On 20,000 `c`
bytes with `aaa` at offset 8191, `tac -r -s aa` printed the literal-scanner
result rather than GNU's.

## Literal reads

Re-verifying the earlier literal window-base fix confirmed its output: the
builtin equals the GNU literal model restricted to real record bytes on
every random case (see below). It also exposed a cost regression. The
search reread its span for every record, so 1 MiB of 33-byte lines took
127,224 positional reads instead of 35. In a gated run that was stopped for
this fix, that input took a median of 72 ms before the regex change and
68 ms after it, against GNU's 5.9 ms. The search now rereads only when
its span leaves the cached block, and then reads a whole block. The test suite bounds positional reads for literal,
byte-atom, engine and glibc separators, on files and pipes.

## Bounded matcher

The separator is parsed with glibc's rules for `RE_SYNTAX_EMACS`, the syntax
GNU tac uses:

- `^` is an anchor only at the start of the pattern or after `\(` or `\|`.
- `$` is an anchor only at the end of the pattern or before `\|` or `\)`.
- A leading repetition character, or one after an anchor, is literal.
- `\{`, `\}`, `|`, `(` and `)` are literal.
- Brackets have no backslash escapes or character classes, so `[[:alpha:]]`
  is a bracket followed by `]`.

Matching uses two lazily built DFAs. A right-to-left automaton finds the
rightmost position where a match can start. A left-to-right automaton then
extends the longest match from that position, which is POSIX semantics.
Anchor contexts follow glibc: word and newline classes, the buffer start and
the search end.

Input is read in 64 KiB blocks. Each DFA cache is limited to 1 MiB and is
discarded when full. Memory therefore depends only on the pattern (at most
4096 syntax nodes and 200 nested groups). Matching is linear in the input,
including on patterns where glibc backtracks exponentially.

The matcher handles these patterns:

- **C/POSIX locale:** every regular pattern.
- **UTF-8 locale:** non-nullable patterns built from ASCII and UTF-8
  literal characters, non-negated ASCII brackets without ranges, grouping,
  alternation, repetition, and the ``^ $ \` \'`` anchors. Every match of such
  a pattern starts on a character boundary, so bytes and characters agree.

Single-byte atoms such as `[,:]+` keep their dedicated scanner.

Everything else goes to the glibc matcher:

- back-references;
- `[.x.]` and `[=x=]`;
- `---` inside a bracket;
- in UTF-8: `.`, `\w \W \s \S`, word anchors, negated or ranged brackets
  and nullable patterns;
- other locales;
- oversized patterns.

The glibc matcher runs `re_search` over GNU's own buffer: the current window
plus the unprinted record. It no longer maps the whole file, and its memory
grows with the pending record, as GNU's does. Its limits are GNU's too. On a
record of 2,148,532,223 bytes, just over `INT_MAX`, both fail with `error
in regular expression search` and status 1, after a 2 GiB peak.
Builds without the GNU regex API run every construct except those, and
reject the rest with `this regex separator requires the GNU regex API on
this build`.

glibc also decides which patterns are valid and supplies the error message,
so invalid separators fail exactly as in GNU tac. The portable parser
reproduces glibc's errors for unmatched brackets and groups, trailing
backslashes, invalid back-references and invalid range ends.

## Options

The parser follows GNU `getopt_long` for `brs:`:

- Short options cluster: `-brs:`.
- `-s` takes the rest of the word or the next word.
- Long options may be abbreviated: `--sep=:`, `--b`.
- Options may follow operands unless `POSIXLY_CORRECT` is set.
- `--` ends option parsing.
- Usage errors return status 1 with GNU's message forms.

`-h` and `-V` remain Bash-OS extensions.

## GNU tac 9.7 defects not reproduced

Defects 1 to 3 are pinned by tests that show GNU's behavior and check the
builtin against an independent oracle.

1. **Anchors in a `+` group.** glibc copies the tree for `X+` (as `X X*`)
   and mis-evaluates anchors inside the copy. GNU gives `.b` for
   `tac -r -s "\(\|\'b\)+"` on `.b`, but `b.` for the equivalent
   `\(\|\'b\)\(\|\'b\)*`. For `` \(\|\`b\)+ `` on `.b`, glibc's
   `re_search` loops forever. The builtin matches GNU's result for the
   spelled-out form. The random-pattern test uses that spelling as the
   oracle whenever a group is repeated with `+`, and accepts a disagreement
   with GNU's original spelling only when an anchor is inside the group.

2. **Stale buffer bytes in the literal search.** After a window widens, the
   pending record can be shorter than the separator. This typically happens
   with `-b` when a match begins exactly at a window base. GNU then compares
   the separator's tail with bytes left in its buffer from an earlier read,
   a previous file, or fresh memory. With 40,000 `c` bytes, `aab` at 8191
   and `b` at 16,384, `tac -b -s ab` treats offset 8191 as a separator
   because of the byte at 16,384. The builtin compares only real record
   bytes.

3. **Spurious `memory exhausted`.** When a file's last window shrinks the
   read size and a later file then doubles it, GNU's new buffer size is
   smaller than the old one. GNU then aborts with `memory exhausted` and
   status 1, losing its unwritten output. Two 40,000-byte files without a
   separator trigger it, with literal or regex separators. The builtin
   prints both files.

4. **Exponential glibc backtracking.** Some nested nullable groups take
   longer than 10 seconds in GNU, on inputs as short as 37 bytes. The builtin finishes in
   linear time. Those random cases have no GNU oracle. They are reported
   and never counted as passes.

5. **Records beyond `INT_MAX`.** GNU searches a regex over one buffer
   holding the pending record, so it fails with `error in regular
   expression search` and status 1 on a 2,148,532,223-byte record without
   a separator, after a 2 GiB peak. The streaming matcher prints that
   record exactly, with a 3,476 KiB peak. This one-off run on a sparse file
   is recorded in the task evidence; it is too large for the suite, which
   instead runs a 48 MiB record under a 32 MiB address-space limit.

For defects 2 and 3, `tests/opus-tac-followup-regex.py` transcribes GNU's
`tac_seekable` literal loop in Python, including buffer reuse across files,
reallocation and the abort. The transcription must reproduce GNU on every
random case, and the builtin must equal the same algorithm restricted to
real record bytes and without the abort. GNU and the builtin may differ
only where the two variants differ.

## Validation

All runs use `PATH=` and `LC_ALL=C` unless noted. Each compares stdout and
exit status byte for byte with GNU tac 9.7 on Debian (glibc 2.41).

- **Retained suites, unchanged:**
  - `tests/tac-parity.py`: 598 checks.
  - `tests/sol-tac-parity.py`: 820 checks.
  - `tests/sol-tac-mapped.sh`: the tac lines of the text-tools and
    repeat-input suites.
  - `tests/input-lifetime.py`: 156 checks with the eight-reader selection.

- **`tests/opus-tac-followup-regex.py`:** 5,310 checks by default.
  - 4,000 grammar-generated Emacs regexes over random and window-straddling
    inputs, run from one persistent shell, plus 400 of them as pipes.
  - Window-base, dot, NUL, anchor and grown-window cases.
  - The glibc matcher on back-references and collating, equivalence and
    `---` brackets, as files and pipes.
  - Invalid patterns.
  - UTF-8 cases on both matchers.
  - 600 random literal cases checked through the GNU model.
  - Ten engine patterns plus a pipe on a 48 MiB record under a 32 MiB
    address-space limit.
  - Positional-read bounds for eight separators, on files and pipes.
  - 40 option-parsing cases with and without `POSIXLY_CORRECT`.

  Extra seeds with 8,000 regex and 1,000 literal cases each are recorded in
  the task evidence. One ran on the final build, three on the build before
  the literal read fix.

- **Sanitizers:** `tests/opus-tac-followup-sanitize.sh` builds the production
  `tac.c` with ASan/UBSan, run through the build gate. It repeats
  `tac-parity.py`, `sol-tac-parity.py` (816 checks applicable to a module)
  and the new suite with 3,000 random cases (4,290 checks).

- **musl:** a static musl 1.2.5 x86-64 build, which has no GNU regex API,
  passes `tac-parity.py` and the new suite with `--portable` (5,308
  checks). The suite requires its 99 glibc-only cases to report the
  unsupported error.

- **RISC-V:** static riscv64 builds against glibc and against musl 1.2.5
  both pass under qemu-user 10.0. Each passes `tac-parity.py` (598 checks)
  and the new suite with 1,500 random cases, the musl build with
  `--portable`. On musl, the 94 glibc-only cases report the unsupported
  error. Each run skips two sections with `--emulated`: the address-space
  section, because qemu-user reserves a 128 MiB JIT buffer, and the
  read-count section, which needs a native `strace`. Both sections ran in
  the native glibc and musl runs.

## Measurements

`bench/opus-tac-followup.py` times the starting build, this build and GNU
tac 9.7 on 1, 4 and 16 MiB inputs, interleaved, with one warm-up and seven
samples each. It runs through the bench gate, pinned to one CPU of an
Intel i7-9850H with glibc 2.41. Every warm-up and sample of all 33 cases
matched GNU's output size and SHA-256 with status 0.

Times are wall-clock milliseconds from a fresh shell, including shell
startup and output file writes. RSS is the peak of the largest single
process. Medians at 16 MiB:

| Workload | Before ms / KiB | After ms / KiB | GNU ms / KiB |
| --- | ---: | ---: | ---: |
| Newline separator | 994.8 / 3,460 | 41.9 / 3,600 | 37.3 / 3,284 |
| One 8 MiB record, file | 17.0 / 3,524 | 16.7 / 3,520 | 29.6 / 9,848 |
| One 8 MiB record, pipe | 34.1 / 3,468 | 31.5 / 3,412 | 48.9 / 10,044 |
| `[,:]+` (byte atom) | 73.2 / 3,496 | 84.9 / 3,536 | 789.1 / 3,276 |
| `BEGIN.*END`, no match, file | 1,013.7 / 19,816 | 227.5 / 3,696 | 1,041.1 / 18,168 |
| `BEGIN.*END`, no match, pipe | 1,011.1 / 18,788 | 226.6 / 3,424 | 1,035.3 / 18,316 |
| `,\\|::` (dense) | 765.1 / 19,840 | 209.7 / 3,620 | 756.4 / 3,396 |
| `^beta` | 519.1 / 19,808 | 125.5 / 3,684 | 494.1 / 3,328 |
| `-r -s ::` | 638.4 / 3,468 | 125.1 / 3,572 | 454.4 / 3,336 |
| `\(:\)\1` (dense back-reference) | 1,830.0 / 19,748 | 1,895.2 / 3,456 | 1,868.9 / 3,296 |
| `\(B\)\1Q`, no match | 14,875.2 / 19,832 | 15,017.5 / 20,048 | 14,682.3 / 18,108 |

The newline workload's "before" time is the literal read regression. At 1 and 4 MiB the
after/GNU medians are 4.14/4.32 and 13.28/13.76 ms.

The bounded matcher keeps general-regex peak RSS near 3.6 MiB at every
size, where the whole-file path grew with the input. It runs 3.6 to 5.1
times faster than both the whole-file path and GNU.

The byte-atom code is unchanged. Its 16 MiB samples overlap:
67–91 ms before and 69–97 ms after. GNU's own samples ranged from 695 to
972 ms in the same rounds, so no difference is claimed.

The back-reference rows use the glibc matcher over GNU's own buffer. Their
time and memory match GNU's, including memory growth with the pending
record: 20 MiB for an unmatched 16 MiB input. That is the documented
limit of the glibc fallback, not a bounded path.

The raw report `bench-opus-tac-followup.json` and its log are in the task
evidence directory, with every sample, binary and source hashes, fixtures,
host load and the method.
