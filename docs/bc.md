# bc — the calculator as a builtin

`bc` evaluates arbitrary-precision decimal arithmetic without leaving the
shell. It is part of the `server`, `desktop` and `full` profiles.

```bash
out/bash -c 'PATH=; bc <<< "scale=20; sqrt(2)"'
1.41421356237309504880
out/bash -c 'PATH=; bc "3^100"'
515377520732011331036461129765621272702107522001
```

Statements come from the standard input, one per line, or from the command
line as a single expression. `scale`, `ibase`, `last` and named variables keep
their values across the lines of one invocation, and start again at their
defaults on the next one — the same state a separate `bc` process would have.

## Repeated calls in one shell

A builtin stays in the shell's process, so it inherits whatever the previous
command left in the C library. `bc` read its input with `getline` on `stdin`,
the stream every builtin shares, and C makes that stream's end-of-file
indicator sticky. The first `bc < file` in a shell reached the end of the file
and set the indicator; every later `bc` saw an immediate end of input and
printed nothing, while still exiting successfully:

```bash
printf '1+1\n' > /tmp/expr
out/bash -c 'PATH=; for i in 1 2 3; do bc < /tmp/expr; done'   # printed one 2
```

The same stream also carries a buffer. Bytes another builtin had read ahead
from an earlier redirection were still in it, and would have been evaluated as
bc input.

`bc` now reads descriptor 0 itself, through a private 4 KiB buffer created for
the invocation and discarded with it. Nothing carries over between calls: the
bytes it sees are the bytes still in the open file description, read in blocks,
which is what a separate `bc` process sees. Three calls now print three
results, and a read error is reported as `bc: standard input: …` with a failure
status instead of being read as an empty input.

The change is confined to input handling. Arithmetic, parsing and printing are
untouched, and every invocation still begins with `scale=0`, `ibase=10` and no
variables.

## What is checked

```sh
python3 tests/bc-parity.py out/bash        # 63 checks against GNU bc
bash tests/bc-sanitize.sh out/bash         # the same checks under ASan/UBSan
python3 tests/large-smoke.py out/bash bc   # the arithmetic fixtures
```

`tests/bc-parity.py` runs each program one, three, five and twenty-five times
in a single shell and compares the whole output with the same number of
external `bc` runs. It covers freshly redirected files, different files between
calls, empty input before and after real input, pipes, here-documents and
here-strings, the shell's own standard input, programs of one line and of a
thousand, a single expression longer than one read block, lines that end
exactly on a block boundary and lines that straddle one, a final line with no
newline, `scale`/`ibase`/variable isolation between invocations, `-l`,
`read()`, expression arguments, syntax errors, divide by zero, an unreadable
input, and the shell reading its own input before and after a call.

## Measured performance

`bench/loadables.py` validates the output of every invocation in a batch before
timing it. Its `bc` case ran the same 18-byte program, `scale=20; sqrt(2)`, as a
builtin, as the BusyBox applet and as GNU bc 1.07.1, all from one bash-os shell,
with each invocation given its own redirection of the fixture. Before the input
fix this case was recorded as INVALID: the batch produced one result instead of
one per invocation, so no builtin timing was published for it.

```sh
python3 bench/loadables.py --only bc --runs 7 --cpu 11 --output /tmp/bc.json
```

Two runs of seven samples each, on the full dynamic `out/bash`, Intel Core
i7-9850H, Linux 6.12.96, pinned to one CPU:

| invocations per batch | bash-os ms | BusyBox ms | GNU bc ms | GNU/bash-os | BusyBox/bash-os |
|---:|---:|---:|---:|---:|---:|
| 74 | 5.897 (5.58–7.70) | 99.388 (92.59–119.58) | 103.802 (100.21–116.00) | 17.6× | 16.9× |
| 80 | 7.261 (6.81–8.05) | 125.961 (108.47–134.36) | 129.093 (123.64–141.19) | 17.8× | 17.4× |

Medians with the observed range. Both runs happened on a busy host — a load
average between 9 and 12, with other builds running — so the absolute
milliseconds are roughly twice what the same fixture costs on an idle machine,
and the two rows disagree accordingly. The ratio within a row is measured from
interleaved runs of the three implementations and was stable across both. The
saving is process creation: the builtin evaluates the program in the shell that
asked for it, while each external run costs a fork and an exec.

The input change itself is not measurable. The previous `getline` reader and the
private buffer were compiled from the same tree with identical flags, loaded
into the same executable with `enable -f`, and each given one invocation reading
an 8.4 MB, 600,000-line program — a workload the previous reader still handled
correctly, since it was the first call in its shell. Seven interleaved runs gave
367.5 ms (326–400) before and 348.6 ms (334–426) after: the ranges overlap.

The remaining cost is per statement, not per byte. Reading and splitting 600,000
lines takes 14 ms; evaluating them as `x=1`, which prints nothing, takes 154 ms;
printing a single digit for each takes another 140 ms; a six-digit addition
brings the total to 456 ms. So roughly 3% of the work is input. The rest is the
digit-string representation — every value is a fresh allocation, and every
result is normalized and copied into `last` — and `bc_print`, which writes one
character at a time. Those are where a future optimization belongs.

## Scope

`bc` implements the POSIX expression surface: `+ - * / % ^`, parentheses,
assignment, `;`-separated statements, `sqrt`, `length`, `scale`, `print`, the
`scale`/`ibase`/`obase`/`last` variables, and the standard math library
(`s c a l e j`) in arbitrary precision under `-l`. It is not a complete GNU bc.
The following are known gaps, confirmed against GNU bc 1.07.1:

| Missing or different | Behavior here |
| --- | --- |
| `define` and user-defined functions | Reports `define/functions are not implemented` and fails the statement. |
| `obase` | Accepted and stored, but results always print in decimal. |
| `if`, `while`, `for`, `break`, `continue` | Syntax error; there is no statement-level control flow. |
| `quit`, `halt` | Read as an unset variable, so they print `0` rather than ending the run. |
| Comments (`/* … */`, `#`) | Syntax error. |
| A bare quoted string as a statement | Syntax error; `print "text"` works. |
| File-name operands | An operand is an expression to evaluate, not a file to read. GNU bc reads named files. |
| A final line with no newline | Evaluated. GNU bc reports a syntax error. |
| Exit status after a syntax or runtime error | `1`. GNU bc reports the error and still exits `0`. |
| Diagnostic wording | `bc: syntax error: TEXT` on standard error, not `(standard_in) N: syntax error`. A failed division prints both a `divide by zero` line and a syntax-error line. |

These are reviewed limits of the current implementation, not an exhaustive
option audit. `tests/bc-parity.py` pins the divergences that have a defined
answer, so a later change to any of them is deliberate.
