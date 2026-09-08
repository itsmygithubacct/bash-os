# nl as a builtin

`nl` numbers lines. As a compiled-in builtin it runs inside the shell's own
process, and that is what made repeated calls wrong: it read standard input
through a stream the whole shell shares.

## Reading the input, not the shell's buffer

The C library's `stdin` stream belongs to the process, and a builtin lives in
the shell's process. Two failures came out of that.

**The stream stays at end of file.** Three calls with a freshly reopened input
produced one copy of the numbered text instead of three:

```sh
printf 'a\nb\nc\n' > input
out/bash --noprofile --norc -c 'for i in 1 2 3; do nl -ba < "$1"; done' _ input
# was: one numbered copy, exit 0.   nl(1): three copies.
```

The first call reached end of file and set the stream's end-of-file indicator.
Bash then applied the next redirection, which installs a new *descriptor* on
file descriptor 0 — but the `FILE` object, and its sticky indicator, is the
same one, so `getline` returned -1 at once and the later calls read nothing and
still exited successfully.

**Another builtin's read-ahead is still in the buffer.** Clearing that
indicator is not enough, because the stream carries bytes as well as flags. A
builtin that buffers more than it prints leaves the rest sitting there, and the
next redirection replaces the descriptor without touching it:

```sh
printf 'first\nleftover\n' > A; printf 'new\ninput\n' > B
out/bash --noprofile --norc -c 'PATH=; head -n1 < "$1"; nl < "$2"' _ A B
# was: first, then leftover numbered 1, then new and input.
# nl(1): first, then new numbered 1 and input numbered 2.
```

`head` printed one line and buffered the rest of `A`; `nl` then read `A`'s
remainder out of the shared buffer before reaching `B` at all.

`nl` therefore does not use the `stdin` stream. It reads the descriptor into
its own per-call buffer, which is what an external `nl(1)` does and the only
way to see the bytes a redirection actually carries — no indicator to go stale,
no buffer to inherit, nothing left behind for the next call. A short read is
processed as it arrives, so a pipe or a terminal still streams line by line,
and FILE operands are opened and read the same way.

It does not consume more than it should: `nl` reads to end of file by
definition, so `{ nl; nl; } < input` still prints one copy, exactly as two
`nl(1)` processes sharing one descriptor would.

## What a call owns, and what it carries

`nl(1)` keeps the line number, the run of blank lines and the current section
in process-wide storage. A fresh process resets them; a builtin has to. All
three now live in call-local state, so:

- every invocation starts at `-v`, in the body section, with no blank run; and
- within one invocation they carry across FILE operands, which is what
  `nl(1)`'s own statics do — `nl -ba -l 2 first second` continues a blank run
  that began at the end of `first`, and a header delimiter at the end of
  `first` leaves `second` in the header section.

## Logical pages

A line consisting only of repetitions of the section delimiter switches
section and, unless `-p` is given, restarts numbering: three repetitions open
a header, two a body, one a footer. The delimiter is `\:` by default and any
string with `-d`; one character is completed with `:`, and an empty string
turns section detection off. The comparison is against the raw line with at
most one trailing newline removed, so `\:\:` followed by a carriage return is
ordinary text. A blank-line run is not interrupted by a delimiter line.

## Output

Output goes through a 64 KiB buffer written straight to the descriptor, after
Bash's own `stdout` is flushed, so text the shell printed before the builtin
still appears before it and Bash's buffering mode is unchanged. A terminal
still receives complete lines while the input stream is open. A failed write
is reported once and the builtin returns failure, so `nl file > /dev/full`
exits 1 instead of exiting 0 having written nothing.

Unnumbered lines reserve the number column and the separator width, line
numbers use `nl(1)`'s three formats (`ln`, `rn`, `rz`, with `-0005` rather
than `0000-5` for a zero-padded negative), and `-w` widths cost no allocation
however large they are. Line numbers are `intmax_t`; when an increment would
overflow, the next line that needs a number reports `line number overflow` and
the builtin fails, which is where `nl(1)` reports it too.

## Bytes and long lines

Records are read with `getline` and written by length, so NUL bytes inside a
line survive and lines are limited only by memory. A `-bp` / `-hp` / `-fp`
regular expression is matched over the line's real length where the platform
offers `REG_STARTEND`, so a pattern can match text after an embedded NUL, as
GNU's length-carrying search does. BusyBox's `nl` ends a line at the first NUL
and has no logical pages, so those inputs are compared against GNU only.

## Tests

```sh
python3 tests/nl-parity.py out/bash        # GNU nl and BusyBox nl parity, shell state
bash tests/nl-sanitize.sh out/bash         # the same cases under ASan and UBSan
```

`tests/nl-parity.py` compares exit status and stdout against `/usr/bin/nl`,
and against `busybox nl` on the option subset and inputs BusyBox supports. It
covers input that follows another builtin's read-ahead — every stdin-reading
builtin in the binary is used as the prefetcher, reading a different file — and
empty input, unterminated final lines, blank-line numbering and `-l`,
every numbering style including regular expressions, formats, separators and
widths, logical-page delimiters and numbering reset, `-p`, long options and
their abbreviations, options after operands, the documented error exits,
several FILE operands, `-` and missing or unreadable operands, long records,
embedded NULs, and the repeated-input loops — fresh redirection, one shared
redirection, a pipe per call, a here-string, a FILE operand, and calls
interleaved with the shell's own `read`. It also checks that Bash's `stdout`
order survives the builtin and that a write failure is reported.

The builtin accepts `-l 0` like GNU 9.7: each blank line is numbered separately.
GNU 9.4 rejects zero. The suite probes the reference and, on that older version,
checks the builtin's `-l 0` output against reference `-l 1`, which has the same
numbering behavior. These cases remain asserted and are reported as contracts;
they are not skipped. Set `NL_REFERENCE=/absolute/path/to/nl` to check another
GNU version, including with the sanitizer harness.

The parity script accepts a shared object in `NL_MODULE` and loads it with
`enable -f`, which is how the sanitizer harness and before/after comparisons
run the same cases against a different build of this file.

## Measurement, 2026-09-08

Only output-validated results are timed. Before this change the harness
reported the builtin as a batch mismatch — 479,435 bytes of the 28,766,100 a
60-call batch should produce, one call's worth — so it had no timing and no
ratio.

```sh
python3 bench/loadables.py --only nl --cpu N --passes 60 --runs 7 \
  --binary out/bash-core --output /tmp/nl.json
```

`nl -ba` over the harness's 423,000-byte word fixture, 60 invocations per
batch inside one `out/bash-core` shell, seven timed runs after the validation
batch, pinned to one CPU of an Intel Core i7-9850H, Linux 6.12.96, GCC 14.2,
Bash 5.3.15, against GNU coreutils 9.7 and BusyBox 1.37.0:

| implementation | median ms | min ms | max ms | vs builtin |
|---|---:|---:|---:|---:|
| builtin | 78.1 | 59.6 | 111.4 | — |
| `/usr/bin/nl` | 220.8 | 183.1 | 271.1 | 2.83× |
| `busybox nl` | 375.5 | 339.6 | 443.8 | 4.81× |

The batch is one process for the builtin and 60 for each external command, so
this measures avoided process creation as much as line numbering. Reading the
descriptor rather than the shared stream cost nothing measurable: the same
case timed at a 2.67× ratio to GNU with the earlier stream reader, under a
lighter load that moved every column by a similar amount. Other work was
active on the host throughout — load average 11 to 15 on twelve CPUs — and the
ranges above overlap, so treat these as a scale, not a maximum-throughput
figure.
