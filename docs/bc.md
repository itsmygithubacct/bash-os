# bc — the calculator language as a builtin

`bc` runs GNU bc programs — arbitrary-precision decimal arithmetic, variables,
arrays, user-defined functions and control flow — without leaving the shell.
It is part of the `server`, `desktop` and `full` profiles.

```bash
out/bash -c 'PATH=; bc <<< "scale=20; sqrt(2)"'
1.41421356237309504880
out/bash -c 'PATH=; bc -e "3^100"'
515377520732011331036461129765621272702107522001
out/bash -c 'PATH=; bc -l <<< "define f(n) { if (n < 2) return (n); return (f(n-1) + f(n-2)) }
obase = 16; f(30); 4*a(1)"'
CB228
3.243F6A8885A308D2A
```

## Invocation

```text
bc [-hilqsvw] [--strict-errors] [-e EXPR] [-f FILE] [FILE...]
```

| Form | What runs |
| --- | --- |
| `bc` | the program on standard input |
| `bc FILE...` | each file in order, then standard input — what GNU bc does |
| `bc -e EXPR -f FILE ...` | the `-e` expressions and `-f` files in the order given; standard input is not read afterwards when any `-e` was given, unless one of the files is `-` |
| `bc -e EXPR` | the argument is a program; standard input is not read |
| `--strict-errors` | return status 1 after a syntax or runtime error, while preserving recovery output |
| `-l`, `--mathlib` | `scale=20` and the library functions `s c a l e j` |
| `-q -s -w -i` | accepted for compatibility and otherwise ignored |
| `-h`, `-v` | usage, version |

Starting with 0.1.2, bare operands always name files, including missing paths
and the literal filename `-`. Use `-f -` to read stdin explicitly. A file that
cannot be opened stops the run with status 1 and leaves subsequent files and
stdin unread, as in GNU bc. A directory is an input error.

Scripts using the former expression-operand extension should change
`bc "3^100"` to `bc -e "3^100"`. The explicit `-e` and `-f` forms (also
`--expression=` and `--file=`) preserve their status 1 after language errors.
Ordinary stdin and bare-file invocation now returns GNU's status 0 after a
recovered syntax or runtime error. Use `--strict-errors` when a script needs
those errors to produce a failing status.

## The language

The language is GNU bc 1.07's, checked against GNU bc 1.07.1 program by
program:

* Numbers of any length and scale; `scale`, `ibase` (2–36, digits `0-9A-Z`),
  `obase` (2 and up; bases above 16 print each digit as a zero-padded decimal
  group, as GNU does) and `last` (also `.`).  A one-digit constant keeps its
  value in any base (`A` is 10), and in a longer constant a digit not below
  the base counts as `ibase-1`, as in GNU bc. At top level constants use the
  current input base, so `ibase=16; FF` on one line is 255. Inside a function,
  constants use the input base captured at entry, after evaluating arguments.
  Changing `ibase` affects subsequent calls immediately, including recursive
  calls, but does not change the current call's constant conversion.
* Variables, arrays `a[i]` (subscripts 0–16777215) and functions in separate
  namespaces: `a`, `a[]` and `a()` are three things.
* `define f(x, a[], *r[]) { auto i, t[]; ... }`: parameters, array parameters
  by value and (`*r[]`) by reference, `auto` locals, `return`, `return (e)`,
  `define void`, recursion and mutual recursion.  Scope is dynamic, as in
  every bc: a call saves the caller's values of its parameters and autos and
  restores them on return — including when a runtime error unwinds the call.
  A redefinition replaces the function.
* `if`/`else`, `while`, `for` (any of its three parts may be empty),
  `break`, `continue`, `{ ... }` blocks over any number of lines, `halt`
  (stops when executed) and `quit` (stops when read, even in a branch not
  taken or a function body).
* `print` lists with the `\a \b \f \n \q \r \t \\` escapes; a bare `"string"`
  statement prints its text as written, newlines included.
* `/* ... */` comments over lines, `#` comments, backslash-newline
  continuation, `limits`.
* `++ --` (prefix and postfix), `= += -= *= /= %= ^=`, relational operators
  anywhere in an expression, `! && ||` with GNU's precedence (`a = 3 < 5`
  assigns 3), `length()`, `scale()`, `sqrt()`, `read()`.

Execution follows GNU bc: a top-level item — the statements up to a newline,
or one function definition — is parsed completely and then run. A syntax
error discards the rest of that line and nothing on it runs; a runtime error
(divide by zero, an undefined function, a parameter mismatch, a negative
square root, a subscript out of range) abandons the rest of the item and
execution resumes with the next one. Expression results are printed unless
the statement is an assignment; `last` holds the last printed value.

Output lines are split like GNU's: when a line reaches `BC_LINE_LENGTH-1`
characters a backslash-newline is inserted, in numbers and strings alike.
`BC_LINE_LENGTH` is read from the exported environment; unset means 70, `0`
disables splitting, and other values below 3 also mean 70. Earlier versions of
this builtin never split lines.

## Compatibility contract

Standard output matches GNU bc 1.07.1 for every program in
`tests/opus-bc-language.py`, including its quirks: zero keeps its scale
(`0/5+1` at `scale=3` is `1.000`), `&&` yields its zero operand rather than 0,
`x op= e` reads `x` before evaluating `e`, a negative power too small for the
scale is a `-0` that compares below zero. Other compatibility contracts and
deliberate differences are:

| Behavior | GNU bc 1.07.1 | This builtin |
| --- | --- | --- |
| Final line without a newline | syntax error, line ignored | evaluated |
| Exit status after a syntax or runtime error | 0 | 0 by default; 1 with `--strict-errors`, `-e` or `-f` |
| Exit status when a named file cannot be opened | 1 | 1 |
| Exit status after an output write error (`/dev/full`) | 1 | 1 |
| Diagnostic text | `(standard_in) 2: syntax error`, `Runtime error (func=f, adr=12): Divide by zero` | `bc: (standard_in) 2: syntax error`, `bc: (standard_in) 1: runtime error (func=f): divide by zero` on standard error, prefixed by the shell; a diagnostic is written exactly when GNU writes one |
| `read()` | reads a number | reads the next line of standard input and evaluates it as an expression in the current `ibase` (the builtin's original contract) |
| Recursion depth | heap-bounded (100,000 calls is fine) | bounded by the C stack: about 7 MiB under the default 8 MiB limit, which is roughly 10,000 nested calls of a simple recursive function; deeper, the item fails with `nested too deeply` instead of crashing the shell, and the same bound applies to absurdly nested source |
| A void function used in an expression | rejected while parsing | the same when it was defined void earlier; a later redefinition is caught when it runs |
| `warranty` | prints the GPL warranty text | prints a one-line MIT notice |
| Interactive use | banner, readline | no banner (as with `-q`), no line editing |
| `-s`, `-w`, `BC_ENV_ARGS`, `POSIXLY_CORRECT` | POSIX checks, extra options | not implemented |

File-open, descriptor read, output and reported resource failures return 1
independently of the language-error status policy. Evaluating a complete final
statement without a newline preserves the explicit expression and redirected
input contracts. This includes complete blocks and function calls; unfinished
strings, comments and blocks still produce diagnostics. A shell here-string
already supplies a newline.

Syntax recovery is not fully identical to GNU's parser. For example, after
`a=7`, the malformed line `a=8; (` followed by `a` leaves `a` equal to 7 in
both implementations, but GNU discards that following statement while this
builtin evaluates it. The reviewed suite retains this output difference as a
failing parity case.

An interrupt (SIGINT) stops a running program at the next loop iteration or
call; the shell then handles the signal as it would for any builtin. Output
goes through a private 8 KiB buffer; a write failure stops the program, even
an endless one, and gives status 1 with `write error`.

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

`bc` reads descriptor 0 itself, through a private 4 KiB buffer created for
the invocation and discarded with it. Nothing carries over between calls: the
bytes it sees are the bytes still in the open file description, read in blocks,
which is what a separate `bc` process sees. A read error is reported as
`bc: (standard_in): …` with a failure status instead of being read as an empty
input. Named files get their own descriptor and buffer, closed when the file
ends.

Every invocation begins with `scale=0` (20 with `-l`), `ibase=10`,
`obase=10`, `last=0`, no variables, no arrays and no functions, and frees all
of them when it returns. `tests/opus-bc-language.py` defines functions and
arrays in one call and checks that the next call sees none of them, runs a
program that allocates on every path 400 times in one shell and checks that
its resident size stays flat, and under `tests/bc-sanitize.sh` checks the same
shell with LeakSanitizer.

## What is checked

```sh
python3 tests/bc-parity.py out/bash          # 119 repeated-input checks
python3 tests/opus-bc-language.py out/bash   # language and contract checks
python3 tests/sol-bc-regression.py out/bash  # independent programs and call-frame regressions
bash tests/bc-sanitize.sh out/bash           # all three under ASan/UBSan (+LSan)
python3 tests/large-smoke.py out/bash bc     # the arithmetic fixtures
```

`tests/bc-parity.py` runs each program one, three, five and twenty-five times
in a single shell and compares the whole output with the same number of
external `bc` runs: freshly redirected files, pipes, here-documents, block
boundaries, a final line with no newline, state isolation, `-l`, `read()`,
syntax and runtime errors, and the arithmetic corner cases (signed and scaled
remainder, fractional divisors, negative powers, square roots).
Arithmetic comparisons set `BC_LINE_LENGTH=0` to keep long GNU results unwrapped.

`tests/opus-bc-language.py` compares standard output, the presence of a
diagnostic and the exit-status contract with GNU bc for:

* about 200 hand-written programs: every statement form, functions with
  scalar, array and reference parameters, autos, recursion (factorial,
  Fibonacci, Ackermann, mutual), error unwinding, `quit`/`halt` placement,
  strings and escapes, comments and continuation lines, nested blocks over
  many lines, and newline placement the grammar does and does not allow;
* base and scale boundaries: `ibase` 2 to 36 and out of range, `obase` 2, 3,
  8, 16, 17, 36, 100, 1000, 65536 and 2147483647, fractions in other bases,
  negative numbers, zero with a scale, `-0`, huge exponents, array bounds;
* the math library under `-l`, including redefinition and `j` with negative
  and fractional orders;
* line splitting at `BC_LINE_LENGTH` 0, 2, 3, 10, 25, 70, unset, `abc`, `-5`;
* 240 random programs from fixed seeds mixing every operator, `scale` up to
  29 and a dozen output bases;
* named files with standard input after them, `quit` and `halt` inside
  files, errors that name the file and line, `read()` from a file program.

It also checks the builtin's own contracts, which have no GNU counterpart:
state reset between calls, recursion that is bounded and cleaned up, nesting
200,000 deep, `-e`/`-f` ordering, the expression form, descriptor counts
after file operands, the final-newline and exit-status table above, output to
`/dev/full`, SIGINT during an endless loop, an empty `PATH`, and usage errors.

## Measured performance

The independent follow-up in [sol-bc.md](sol-bc.md) covers function input-base
capture, function-table relocation during `read()`, unary stack bounds and
fresh before/after allocation and output measurements. Its evidence supersedes
the implementation claims below where those defects were involved.

The measurements below describe revision `66ddbd7`, before duplicate `auto`
declarations and parameter/`auto` collisions were rejected. They do not measure
the corrected parser. Scalar and array names remain separate namespaces.

`bench/opus-bc.py` times fixed programs through this builtin, the previous
builtin (source `5a91c6e`) and GNU bc 1.07.1, all launched from the same
bash-os shell family with the fixture redirected onto standard input and
`BC_LINE_LENGTH=0`. GNU's output for each fixture is the expected output; every
run, the warm-up included, is checked against it, and an implementation with
a wrong output or status is INVALID for that workload, with no timing
published. The previous builtin is INVALID wherever the program needs loops,
functions or `obase` — it could not run them. `--alloc` counts heap calls with
the `bench/opus-bc-alloc.c` preload shim and `--syscalls` counts read/write
calls with strace, both in separate validated runs, net of the same shell loop
running `:`.

```sh
python3 bench/opus-bc.py --before OLD/bash --after out/bash --runs 7 --cpu 5 \
    --alloc alloc.so --syscalls --output report.json
python3 bench/loadables.py --only bc --passes 80 --runs 7 --cpu 5 --output bc.json
```

Seven samples after one warm-up, pinned to one CPU of an Intel Core i7-9850H,
Linux 6.12.111, load average 3–4 from other builds; medians with the
observed range in milliseconds:

| workload | work | old builtin ms | new builtin ms | GNU bc ms | new/GNU | new/old | heap calls old → new | write calls old → new (GNU) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| arithmetic | 80 x (scale=20; sqrt(2)) | 13.2 (12.7–14.3) | 14.1 (13.2–15.0) | 79.3 (77.5–89.0) | 0.18× | 1.07× | 6163 → 6323 | 80 → 80 (80) |
| assign-lines | 200000 statements | 36.7 (33.0–75.0) | 65.9 (59.9–97.2) | 97.7 (73.5–151.5) | 0.67× | 1.79× | 600006 → 200010 | 0 → 0 (0) |
| print-lines | 100000 statements, 100000 output lines | 98.7 (93.9–104.9) | 75.5 (68.7–78.4) | 164.3 (157.6–180.6) | 0.46× | 0.77× | 700007 → 300011 | 100000 → 287 (100000) |
| add-lines | 100000 additions | 93.2 (82.1–103.3) | 66.1 (59.8–77.0) | 148.1 (126.7–166.3) | 0.45× | 0.71× | 500005 → 800007 | 100000 → 341 (100000) |
| big-output | 2709300 output digits | 102.2 (101.1–110.0) | 6.0 (5.9–6.4) | 50.3 (49.2–60.3) | 0.12× | 0.06× | 955 → 694 | 900 → 719 (900) |
| for-loop | 200000 iterations | INVALID | 41.1 (40.7–42.0) | 64.3 (62.3–67.6) | 0.64× | — | — → 400020 | — → 1 (1) |
| loop-print | 100000 iterations, 100000 output lines | INVALID | 21.3 (20.5–23.3) | 97.8 (95.1–100.6) | 0.22× | — | — → 300016 | — → 287 (100000) |
| recursion | 57313 user function calls | INVALID | 14.2 (14.1–14.7) | 26.1 (25.6–26.7) | 0.55× | — | — → 114650 | — → 1 (1) |
| obase-output | 10 x 2501 hex digits | INVALID | 17.0 (14.3–23.9) | 2329.0 (2259.7–2698.1) | 0.01× | — | — → 125 | — → 10 (10) |

Over the work, in four measured steps (raw reports kept with the task
evidence):

* A tree interpreter on the old number core (v1) had 9 heap calls per
  assignment line against the old builtin's 3, and was 3.2× slower on
  `assign-lines`. Products digit by digit and output-base conversion by one
  digit per pass made `big-output` 95 ms and `obase-output` (then 2^20000
  forty times) 13.2 s.
* Node blocks instead of one allocation per node, operands read in place,
  assignments that move their value, and allocation-free loop conditions
  took `for-loop` from 2,000,051 to 400,020 heap calls and 99.8 to 40.6 ms,
  and `recursion` from 515,867 to 229,290. Base-10^9 multiplication took
  `big-output` from 95.7 to 7.1 ms; chunked radix conversion took
  `obase-output` from 525 to 17 ms (GNU: 2,337 ms).
* Token text kept in the token, a reused first node block and shared
  one-digit constants took `assign-lines` from 1,000,007 heap calls to
  200,010 — one per line, the value stored — and from 97 to 65 ms.
* Smaller frames on the recursion path (which raised the depth limit from
  about 3,000 to about 10,000 calls) changed no timing beyond noise.

Output is the clearest cost removed: the previous builtin wrote through
`putchar` and the shell's stdout made one `write` per line, 100,000 for
100,000 lines, as GNU bc also does; the private buffer writes 287.
`assign-lines` remains 1.8× the previous builtin, which evaluated each line
directly while parsing it; this one builds and runs a tree per item, which is
what makes functions and control flow possible. It is still faster than GNU.
`add-lines` makes 8 heap calls per line (the two constants' texts are copied
into the tree, converted and copied again for evaluation), against the old
builtin's 5, but is faster.

The historical `bench/loadables.py` case (80 invocations of
`scale=20; sqrt(2)` per sample) measured 14.08 ms (13.6–15.0) for the
previous builtin and 15.14 ms (14.2–16.0) for this one in interleaved
sessions minutes apart, with GNU bc at 79.7 and 87.3 ms and BusyBox at 75.3
and 83.5 ms; the per-invocation difference, about 13 µs, is within the spread
of earlier sessions (13.0 and 14.3 ms). Per call the builtin remains about
six times cheaper than starting GNU bc.

### Historical: the input fix

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

At the time, the remaining cost was per statement, not per byte. Reading and splitting 600,000
lines takes 14 ms; evaluating them as `x=1`, which prints nothing, takes 154 ms;
printing a single digit for each takes another 140 ms; a six-digit addition
brings the total to 456 ms. So roughly 3% of the work is input. The rest is the
digit-string representation — every value is a fresh allocation, and every
result is normalized and copied into `last` — and `bc_print`, which writes one
character at a time. Those are where a future optimization belongs.

## Implementation notes

Numbers are decimal digit strings with a scale. Products of more than 40
digits are computed nine digits at a time in base 10^9; output in another base
divides base-10^9 limbs by the largest power of the base that fits 32 bits.
The parser builds a tree per top-level item from a small node block; names
are resolved to slots once, when parsed. Values are copied only when they
must be: an operand that is already a variable or a constant is read in place
when nothing evaluated after it can change it, a statement-level assignment
moves its value into the variable, and loop conditions compare without
materializing a 0 or 1. The math library is a port of GNU's `libmath.b`
series onto this number core, so its digits match GNU's at every scale.
