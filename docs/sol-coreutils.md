# Coreutils dispatcher validation

**Validation status: incomplete.** The baseline focused checks reproduced 184
failures. The first modified native build failed because the existing `fmt`
output helper had been removed along with the former `tac` implementation; that
helper is restored in the final source. The corrected build, sanitizer run and
all timing/profile jobs were blocked by the campaign resource gate. Python/shell
syntax and whitespace checks pass, but the final source has not been compiled
or exercised. No new timing or speedup claim is established. Run the checks below
before integration, then collect baseline/final reports using the preserved
baseline binary and source snapshot.

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
