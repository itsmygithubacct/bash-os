# pr — pagination and column formatting

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
| `-w WIDTH`, `--width` | positive page width for column layout, default 72; an impossible column geometry fails |
| `-h HEADER`, `--header` | replace the page title |
| `-COLUMN`, `--columns=COLUMN` | lay one input out in N balanced columns |
| `-a`, `--across` | fill those columns left to right instead of top to bottom |
| `-m` | merge: read every FILE in parallel, one column each |
| `-n[SEP][DIGITS]` | number records: `-n`, `-n3`, `-nc3`, `-n:` |
| `-o OFFSET` | indent every line by OFFSET columns |
| `-s[STRING]` | join columns with a separator string (default TAB); explicit `-w` retains column alignment and truncation |
| `-d`, `--double-space` | a blank line after each record, in single and column layouts |
| `-f`, `-F`, `--form-feed` | separate pages with a form feed instead of blank padding |
| `--help`, `--version` | usage text; the loadable's own version string |
| `--` | end of options |
| `FILE...`, `-` | operands; `-` and no operand are standard input |

Invalid options and arguments now return GNU's failure status 1 (the previous
loadable returned Bash usage status 2). The tests compare this status directly
with GNU; diagnostics retain Bash's command prefix.

Options may follow operands. Attached required arguments and short-option
clusters are accepted; optional arguments attach to their option (`-e4`,
`-n:3`, `-S::`) or use the long option's `=` form.

Additional GNU surfaces include `-c`/`--show-control-chars`,
`-v`/`--show-nonprinting`, `-e[CHAR[WIDTH]]`/`--expand-tabs`,
`-i[CHAR[WIDTH]]`/`--output-tabs`, `-J`/`--join-lines`,
`-S[STRING]`/`--sep-string`, `-W WIDTH`/`--page-width`,
`-D FORMAT`/`--date-format`, `-r`/`--no-file-warnings`,
`-T`/`--omit-pagination`, `-N NUMBER`/`--first-line-number`,
`+FIRST[:LAST]`/`--pages=FIRST[:LAST]`, and GNU long names for the
short options in the table. `-W` applies truncation even to a single column;
`-J` joins complete records. `-S` controls the separator independently of
width; it overrides the older `-s` interaction. A custom first line number
starts at the first page printed; default numbering counts skipped input.

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

A record ends at a newline or input form feed; a final unterminated record
is still printed. A form feed ends the input page and consumes an immediately
following newline. `-T` suppresses its output byte. NUL bytes and other control bytes are carried through,
and a carriage return is part of the record rather than a terminator. Records
of any length are read, including ones longer than the 64 KiB input buffer.

In a multi-column layout the column arithmetic follows GNU pr: a printable byte
occupies one column, an input TAB advances to the next eight-column stop
measured from the start of its cell, a backspace moves back one, any other byte
occupies none, and the resulting spacing is re-emitted with TABs. Ordinary single-column output preserves the input bytes, except backspaces
that would move before the start of an input record. The conversion options
apply when requested. Columns are truncated to their width; `-W` also enables
truncation for single-column output.

## Qualification limits

The original named exclusions for numbered control bytes, merged unterminated
records, narrow widths, string separators, post-operand options and column
counts above nine are exercised by assertions in `tests/pr-parity.py` and
`tests/sol-pr-cli.py`. Test and measurement qualification, including remaining
core limitations, is recorded in [the implementation report](sol-pr.md).
`--version` identifies the loadable rather than a coreutils release. GNU's
translated diagnostics and unique long-option abbreviations are outside this
CLI compatibility scope.
