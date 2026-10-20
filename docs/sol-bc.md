# bc independent completion review

The starting implementation at `15ebebe` included the language rewrite
(`299dbbe`) and duplicate-local validation (`a4a260d`). Its 119 repeated-input
checks and 571 language checks passed before these changes. Independent
programs nevertheless exposed four defects:

* Constants inside a function followed the mutable global `ibase`. GNU
  captures the base after argument evaluation, separately for each call.
  For example, `define f(){ibase=2;return 10}` followed by `f()` returns 10,
  then a top-level `10` returns 2. Nested and recursive calls now preserve
  that distinction.
* `read()` can parse expressions that introduce function names. Growing the
  function table invalidated pointers held during argument binding and
  math-library dispatch. ASan reported heap-use-after-free in both paths;
  without ASan, `s(read())` could return 1 for an input expression equal to
  zero. Call metadata now survives table relocation.
* A sufficiently long unary-expression chain overflowed the shell's stack
  during parsing. Unary parsing and the expression-purity walk now obey the
  same stack budget as evaluation, report a nesting error, and let the shell
  execute the next command.
* A descriptor error inside `read()` returned a successful zero. It now
  reports the input error and returns status 1.

No shared helper changed. The focused build includes
`bc,head,sed,fold,expand,nl,pr,tac` so the existing mixed-reader integration
suite can run. `bc` itself requires no companion command.

## Independent coverage

`tests/sol-bc-regression.py` compares complete programs with GNU bc 1.07.1:
Euclid's algorithm, recursive quicksort with reference arrays, recursive
local arrays, dynamic-state restoration after errors, nested calls with
changing input bases, and comments/strings/continuations across input-buffer
boundaries. The base matrix combines six input bases, seven output bases
(including 2147483647), and three scales. Arbitrary-precision arithmetic and
all six math-library functions are checked through scale 55.

Builtin-specific checks cover explicit expression/file disambiguation,
file ordering followed by stdin, missing files, descriptor ownership,
function-table growth during `read()` with stack and heap argument arrays,
repeated-call reset after recursion errors, and output failure followed by a
successful invocation. A 512 KiB stack fixture checks deep unary parsing and
expression traversal without crashing the shell.

The final-newline and exit-status contracts are tested explicitly:

| Case | GNU bc 1.07.1 | Builtin |
| --- | --- | --- |
| Complete final statement or block without newline | ignored with syntax error, status 0 | evaluated, status 0 |
| Syntax/runtime error followed by valid input | later input executes, status 0 | later input executes, status 1 |
| Missing named file | status 1 | status 1 |
| Output to `/dev/full` | status 1 | status 1 |
| Unfinished comment or string | diagnosed | diagnosed, status 1 |

The newline tolerance, expression-valued `read()`, bounded C-stack recursion,
and unsupported compatibility options remain explicit contracts in
[bc.md](bc.md). This review does not claim every GNU option or diagnostic
wording matches. Native x86-64 validation does not replace cross-libc or
RISC-V integration testing.

```sh
./build.sh --include bc,head,sed,fold,expand,nl,pr,tac --name bc-review
python3 tests/bc-parity.py out/bash-bc-review
python3 tests/opus-bc-language.py out/bash-bc-review
python3 tests/sol-bc-regression.py out/bash-bc-review
python3 tests/large-smoke.py out/bash-bc-review bc
python3 tests/input-lifetime.py out/bash-bc-review
bash tests/bc-sanitize.sh out/bash-bc-review
```

The sanitizer runner includes all three dedicated suites; its inherited
400-call churn fixture also uses LeakSanitizer. During the completion
campaign, run compilation (including the sanitizer runner) through the build
gate, and measurement through the bench gate.

Final native results: 183 independent checks, 571 inherited language checks,
119 repeated-input checks, 156 mixed-reader checks, and 9 focused smoke
checks. ASan/UBSan passed 183, 570 and 119 checks respectively in the three
dedicated suites, including the leak-churn fixture. The inherited sanitizer
suite uses a smaller successful-recursion depth and omits its native-only
8,000-call test; the native run passed that test.

## Measurement method

`bench/sol-bc.py` reuses the fixed programs from `bench/opus-bc.py` and checks
GNU's expected outputs against independently calculated Python integer and
Decimal results before timing. It records source hashes, binary hashes and
build manifests, versions, fixture/output hashes, CPU affinity, host/load
information, seven samples after a warm-up, and validation of every pass.
Implementation order reverses on alternate rounds. Any invalid workload
makes the adapter fail. The old and new executables
use identical compiler flags and command selections on the same host.

Each arithmetic sample runs 80 invocations in one shell, with a fresh
redirection and interpreter state for every invocation. The larger programs
run once per sample. Output goes to a regular file and is checked byte for
byte after each warm-up/timed run. The external reference pays process
creation; the builtin does not.

Allocation and read/write counts are separate instrumented runs. Builtin
allocation counts subtract the same shell loop executing `:`. The preload
shim's external allocation counters cover the launching shell, so they are
not used to compare GNU's internal allocation cost. Syscall counts include
descendants. Raw reports are retained with the task evidence, independently
of the historical reports in `bc.md`.

```sh
cc -O2 -fPIC -shared bench/opus-bc-alloc.c -ldl -o alloc.so
python3 bench/sol-bc.py --before OLD/bash --after NEW/bash \
  --before-source OLD/bc.c --after-source loadables/bc.c \
  --runs 7 --alloc ./alloc.so --syscalls --output report.json
```

## Matched results

Measured on 2026-10-20 with GCC 14.2.0, Bash 5.3.15 and GNU bc 1.07.1,
Intel Core i7-9850H, Linux 6.12.111, pinned to CPU 11. Both builds used
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2` and the same eight-command
selection. Seven samples follow one warm-up, with alternating implementation
order; every output and status passed validation. Times are median (minimum–
maximum) milliseconds; counts are net of the empty shell loop.

| Workload | Predecessor ms | Corrected ms | GNU ms | malloc calls before → after | writes before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| arithmetic | 16.37 (16.24–23.76) | 16.49 (16.15–17.08) | 95.96 (95.23–107.06) | 5763 → 5763 | 80 → 80 |
| assign-lines | 66.19 (63.90–75.56) | 69.09 (65.20–81.35) | 88.73 (80.76–93.63) | 200006 → 200006 | 0 → 0 |
| print-lines | 86.09 (80.58–98.17) | 79.88 (75.51–86.57) | 195.86 (176.75–207.63) | 300007 → 300007 | 287 → 287 |
| add-lines | 84.44 (74.23–99.69) | 81.70 (69.81–104.60) | 190.27 (173.85–233.42) | 800005 → 600005 | 341 → 341 |
| big-output | 8.60 (6.96–12.00) | 7.21 (6.78–8.83) | 62.52 (60.73–66.70) | 657 → 656 | 719 → 719 |
| for-loop | 50.32 (45.59–53.58) | 50.32 (46.62–59.22) | 81.16 (76.24–83.09) | 400016 → 400015 | 1 → 1 |
| loop-print | 23.62 (21.21–28.88) | 25.66 (22.48–28.31) | 117.43 (105.09–126.91) | 300012 → 300011 | 287 → 287 |
| recursion | 15.58 (15.18–17.44) | 17.01 (16.70–17.32) | 28.69 (28.57–40.44) | 114642 → 114642 | 1 → 1 |
| obase-output | 12.56 (10.28–19.08) | 12.39 (11.13–17.67) | 2812.40 (2391.71–2957.21) | 93 → 92 | 10 → 10 |

Host load averaged 3.83 at entry and
4.11 at exit. The predecessor binary SHA-256 is
`50d19178b219ef379f13c7c92287c565f5c9c4f2a893e1f1f2eb7f117de1b42b`; the corrected binary is
`ed503f3443cf3297e89e313292951819a46441ced13aaf07c8042e2081870182`. The measured corrected `bc.c` SHA-256 is
`811126c56dae7c2d718d181d5e934fd1c1aa545972a35e4dc874d20ca6e71658`. Full sample distributions, fixtures,
independent expected-output hashes, tool versions and counting runs are in
`bench-paired-final-v3.json` in the task evidence.

The allocation fix removes two temporary number copies per addition in
`add-lines`: 800,005 → 600,005 net malloc calls (25% fewer), and approximately
1.4 MB fewer allocation requests per sample. Numbers are converted into their
AST cache and borrowed directly when the other operand cannot invalidate
them. Assignments still allocate their stored value, and statement parsing
still builds a tree; those costs were not removed.

Output buffering already worked in the predecessor. Both versions make 287
writes for the 100,000-line counter workloads, rather than GNU's 100,000.
The 80-invocation arithmetic workload has unchanged allocation and write
counts. There is no new output-buffering speedup to claim. The raw preliminary
profile (`bench-before.json`) and fixed-order paired run
(`bench-paired-final-v2.json`) are preserved separately. The latter had large
base-conversion timing variation and prompted alternating the order in the
final run; it is not combined with this report.

Timing ranges overlap on many workloads. Correctness checks add work, and
this patch is not a uniform speed improvement: the table retains regressions
as well as improvements. The exact allocation reduction is stronger evidence
than a small wall-time change on this shared host. The historical performance
numbers in `bc.md` describe other revisions and sessions and are not paired
with these results.
