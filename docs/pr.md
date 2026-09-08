# pr — the supported subset

[`loadables/pr.c`](../loadables/pr.c) is a paginator and column formatter in
the shape of POSIX `pr(1)`. It is compared byte for byte with GNU coreutils
`pr` by [`tests/pr-parity.py`](../tests/pr-parity.py), which also checks what
survives from one invocation to the next inside a single bash-os shell.
[`tests/pr-sanitize.sh`](../tests/pr-sanitize.sh) repeats the same checks with
the loadable rebuilt under AddressSanitizer and UndefinedBehaviorSanitizer.

This page records what that comparison covers. It is a subset: `pr` here is not
a drop-in GNU `pr`, and the differences that remain are listed at the end.

## Options

| option | behaviour |
| --- | --- |
| `-t` | no header, no footer, no page padding |
| `-l LINES`, `--length` | lines per page (default 66). A page of ten lines or fewer has no room for the five-line header and five-line footer and is printed without them, as in GNU pr. Zero is an error. |
| `-w WIDTH`, `--width` | page width for column layout, default 72, **minimum 8** |
| `-h HEADER`, `--header` | replace the page title |
| `-N` (a bare digit 1–9) | lay one input out in N balanced columns |
| `-a`, `--across` | fill those columns left to right instead of top to bottom |
| `-m` | merge: read every FILE in parallel, one column each |
| `-n[SEP][DIGITS]` | number records: `-n`, `-n3`, `-nc3`, `-n:` |
| `-o OFFSET` | indent every line by OFFSET columns |
| `-s[SEP]` | join columns with one separator character (default TAB) and stop padding and truncating |
| `-d`, `--double-space` | a blank line after each record, in single and column layouts |
| `-f`, `-F`, `--form-feed` | separate pages with a form feed instead of blank padding |
| `--help`, `--version` | usage text; the loadable's own version string |
| `--` | end of options |
| `FILE...`, `-` | operands; `-` and no operand are standard input |

Options must precede the operands. GNU pr also accepts them afterwards.

## Page dates

A page is dated from the **file's modification time**, and from the current
time when the input is standard input or when several files are merged, which
is what GNU pr does. A merged page's title is blank. Fixing a file's
modification time, `TZ` and `LC_ALL` therefore makes a header reproducible,
which is how the parity tests compare them.

## Invocation and output state

Bash runs a builtin inside one long-lived process, so anything left behind in
the C library's `stdin` and `stdout` objects outlives the call. `pr` reads its
records straight from the descriptor into a buffer owned by the invocation, and
writes through a 64 KiB buffer of its own. Consequences worth relying on:

- Three `pr -t < file` calls in one shell each print the whole file. Reading
  through `stdin` made the second and third print nothing, because the first
  call's end-of-file indicator survived them; that was the failure recorded for
  `pr` in the [loadable status table](loadables-status.md#repeated-input-findings).
- Another builtin that reads the same descriptor first — `read`, `head` — does
  not change what `pr` then reads. A builtin that stops part way leaves bytes
  in the shell process's own `stdin` object: with `A` holding `first`,
  `leftover` and `B` holding `new`, `input`, `head -n1 < A; pr -t < B` printed
  `leftover` before `B`'s records. Clearing the end-of-file indicator alone
  would not have fixed that; reading the given descriptor does.
- Two calls sharing one open descriptor (`pr -t <&9` twice) see one stream
  between them, exactly as two GNU `pr` processes would.
- A failed write is reported as `write error: …` and returns 1. The shell
  carries on: the next call still produces its whole page.
- A terminal receives complete lines while the input stream is still open.

## Records

A record is the bytes up to and including its newline; a final record without
one is still a record. NUL bytes and other control bytes are carried through,
and a carriage return is part of the record rather than a terminator. Records
of any length are read, including ones longer than the 64 KiB input buffer.

In a multi-column layout the column arithmetic follows GNU pr: a printable byte
occupies one column, an input TAB advances to the next eight-column stop
measured from the start of its cell, a backspace moves back one, any other byte
occupies none, and the resulting spacing is re-emitted with TABs. A single
column is a byte-for-byte pass-through, as in GNU pr. Column contents are
truncated to the column width; a single column is never truncated.

## Differences from GNU pr

These are known and deliberate; the parity test skips them by name.

- **Numbered column layouts of records holding control bytes.** With more than
  one column, `-n` *and* either a custom `-n` separator (`-nc3`, `-n:`) or the
  default-TAB `-s`, a record containing a TAB, CR or NUL is spaced differently
  from GNU pr. Plain records match in every layout the test covers.
- **`-m` with `-n` over a file whose final record has no newline.** GNU pr
  emits a second number field part way through that output row and skips a
  number; `pr` here numbers output rows consecutively.
- **`-w` below 8** is a usage error rather than a narrow page.
- **`-s` takes one separator character.** GNU pr takes a string.
- **Options after the first operand** are treated as operands.
- Not implemented: `-c`, `-e`, `-i`, `-J`, `-r`, `-S`, `-T`, `-v`, `-D`,
  `+FIRST[:LAST]`, and column counts above 9.
- `--version` reports the loadable, not a coreutils release.
