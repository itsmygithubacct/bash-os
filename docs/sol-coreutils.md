# Coreutils dispatcher validation

**Native validation completed for the bounded subsets below.** The original
failed build and resource-blocked attempts remain preserved as failed evidence.
An isolated build of the committed source now passes the focused dispatcher
suite, retained nproc, coreutils smoke, install and fastpath checks. ASan/UBSan
passes both the focused suite and 14 controlled production entropy checks.
The restored `fmt` helper compiles without further source changes.

All 16 workloads (12 verbs plus a second factorization and three extra tac
shapes) pass warmup and seven samples with exact output/status or the stated
random/pipeline invariants. The preserved baseline fails repeated-stdin tac:
only the first of 30 calls produces output. That case has no valid baseline
timing or ratio. Native qualification is x86-64 Linux/glibc; it does not add
static, musl, RISC-V, physical erasure or live-device qualification.

The dispatcher implements twelve bounded command subsets. The focused completion
work covers literal `tac`, affinity and OpenMP processor selection, seeded shuffle
fixtures, private-file shred invariants, and independent measurements of every
verb. It does not claim full GNU option compatibility.

`tac` reads file descriptors so repeated input redirections in one shell do not
retain a previous invocation's EOF state. It consumes literal separators from the
right, including overlapping matches, and treats an empty separator as NUL.
Records retain their trailing separator; an unterminated final record receives
no extra byte. Each file reverses independently in operand order. Input remains
buffered in memory, but output no longer needs a separate array per record. It
uses the existing `bl-output.h` buffer without changing that shared helper.
The dispatcher's `-b` and `-r` options remain unsupported.

`nproc` uses affinity unless `--all` requests configured processors. A positive
`OMP_NUM_THREADS` replaces the affinity count, even when larger than the mask;
`OMP_THREAD_LIMIT` caps either that override or the normal count. `--all` ignores
both variables. Whitespace and the first comma-separated nesting level are
accepted; zero and malformed values are ignored. Overflow saturates to
`ULONG_MAX`, matching the installed GNU oracle. `--ignore=N` and `--ignore N`
subtract after selection and floor the result at one; malformed arguments fail.
The focused assertions compare these semantics with [GNU nproc 9.7](https://github.com/coreutils/coreutils/blob/v9.7/src/nproc.c)
and [gnulib's environment parsing](https://github.com/coreutils/gnulib/blob/master/lib/nproc.c).
The affinity implementation still uses a fixed `cpu_set_t`, and this scope does
not add cgroup CPU-quota detection.

`shuf --random-source=FILE` uses up to eight bytes as a big-endian xorshift seed,
using the available bytes of a short source and a fixed nonzero state for an all-zero or
empty source. An unreadable source fails. This is a repeatable fixture interface,
not GNU's random-byte algorithm or a cryptographic generator. Tests assert a
fixed eight-byte seed's permutation and independently check membership,
multiplicity, limits and repeatability. Unseeded shuffling and random shred
passes are checked by invariants. Shred tests mutate only private files; zero
passes have exact byte expectations. Read, write, seek, sync and close failures
prevent a success status and prevent requested unlinking after an unsuccessful
overwrite. These checks do not qualify physical secure erasure.

Run correctness checks with a focused build:

```sh
./build.sh --include coreutils,tac --name sol-coreutils --no-strip
python3 tests/sol-coreutils-check.py out/bash-sol-coreutils
bash tests/nproc-check.sh out/bash-sol-coreutils
python3 tests/large-smoke.py out/bash-sol-coreutils coreutils
python3 tests/coreutils-fastpaths.py out/bash-sol-coreutils
bash tests/sol-coreutils-sanitize.sh out/bash-sol-coreutils
```

The sanitizer script compiles instrumented copies of the actual production
modules, then exercises the same assertions. A test-only `fopen` link wrapper
also maps production entropy reads to private byte fixtures, checking exact
one- and two-pass shred bytes and failures when entropy is short or absent. During the completion campaign,
every build, including that script, must run through the build gate, and every
benchmark or profile must run through the bench gate. The only companion selected
for these tests is standalone `tac` as an additional oracle; `coreutils` has no
required companion entry in `config/helpers.json`. The normal build automatically
stages its default `_jsmn` helper.

`bench/sol-coreutils.py` records separate cases for every verb plus large-factor,
redirected-stdin, binary and dense-record workloads. Each warm-up and each timed
batch validates all output records and statuses. It uses seven samples, thirty
calls per batch and the gate's fixed CPU affinity. Original `left`, `text` and
`chain` fixture bytes match the historical harness. It records source and binary
hashes, reference hashes, tool versions, environment, fixture hashes, work units
and complete sample distributions. Mutating install/FIFO/shred cases include
common readback or cleanup subprocesses and therefore measure the stated whole
work unit. Shred starts each batch with 8192 `x` bytes and overwrites the same file
every pass. Shuffle permutations differ from GNU and receive invariant-validated
self timings without a ratio. The bounded `yes` pipeline consumes 4096 records;
producer overshoot is unspecified, so it also receives self timings only.

## Validated dispatcher measurements

Median milliseconds for 30 calls per sample, CPU 11, one warmup and seven
samples. These runs measure the committed implementation described above;
the review correction changes documentation only. Baseline and final runs
were sequential, so no paired before/after speedup is claimed.

| tac workload | Dispatcher | GNU | Standalone |
| --- | ---: | ---: | ---: |
| 120,000-byte file | 10.866 | 39.773 | 11.806 |
| 120,000-byte redirected stdin | 9.097 | 33.683 | 10.583 |
| 262,404-byte binary file | 9.148 | 47.751 | 9.382 |
| 1,000,000-byte dense records | 308.131 | 400.213 | 389.075 |

The final `fmt` batch remains slower than GNU (122.091 versus 107.542 ms).
There is no uniform dispatcher speedup claim. Shuffle and bounded `yes`
receive self timings only; their invariants do not establish equivalent
random streams or producer work for a throughput ratio.

Owned-process syscall profiles validate 500 repetitions of the 120,000-byte
tac fixture before and after. Dispatcher writes fall from 223,499 to 1,000,
consistent with replacing line-buffered stdio delivery with the existing
block output helper. These are observed syscall counts, not isolated timing
attribution. The GNU profile traces its parent shell without `-f`, so its
counts cannot be compared with the builtin's utility work. Hardware-counter
profiling was denied by kernel policy (`perf_event_paranoid=3`); no policy
was changed and no counter-based conclusion is claimed. Full distributions,
hashes and unsuccessful attempts remain outside the published source tree.
