# PCRE implementation and validation

`pcre` uses the selected libpcre2-8 without JIT. Build it alone with
`./build.sh --include pcre --name sol-pcre`; no companion loadable is required.
The optional `binhex` command is a convenience for callers, not a dependency.

The API is `match`, `subst`, `find-all`, `grep`, and `sed`. It does not expose
compiled-pattern handles: `compile` and `free` are invalid subcommands. A
16-entry LRU retains patterns and their reusable match data. Its key includes
compile flags and the complete pattern byte length, including embedded NULs.
Eviction frees both objects; dynamic unload frees the cache and match context.
Unique patterns measure compilation on every call; a repeated pattern measures
cache lookup, matching, conversion, and shell binding. These are distinct work
units, not interchangeable claims about PCRE2 engine throughput.

`match` replaces `BPCRE_MATCH` with an indexed array containing the full match
and participating numbered captures. Unset groups have absent indices; failure
clears earlier captures after argument validation. Writable scalars and
associative arrays are replaced. Readonly variables and namerefs fail before
matching and preserve their targets. Local arrays retain their function scope
and are made visible after successful binding. No raw pointer or stale pattern handle can be supplied by the caller.

Text mode enables UTF and Unicode properties. `-b` selects bytes. `-X` on
`match`, `subst`, or `sed` transports patterns, subjects, replacements, and
results as hexadecimal bytes, including NULs, and selects bytes mode by
default. An inline PCRE2 directive can still enable UTF. `grep` and `find-all`
reject `-X`. Options are individual flags before `--`; operands after `--`
are literal, allowing patterns such as `-a`. Stream commands accept at most
16 files and reject excess operands explicitly.

Replacement supports PCRE2 `$1`/`${name}` and the existing `\1`/`\g<name>`
aliases. Output sizing uses `PCRE2_SUBSTITUTE_OVERFLOW_LENGTH`, including large
expansions, with checked allocation. `find-all` retries empty matches anchored
at the same offset before advancing one character, and respects the compiled
pattern's UTF and CRLF newline settings.

Default matching limits are 1,000,000 steps, depth 10,000, and 16 MiB of PCRE2
backtracking heap per match-data block. Exported `BASHPCRE_MATCH_LIMIT` and
`BASHPCRE_DEPTH_LIMIT` are refreshed each command; decimal values from 1 through
UINT32_MAX are accepted. Empty, zero, signed, malformed, and overflowing values
use the bounded defaults. Allocation failure never falls back to an unbounded
match context. Engine/limit failures produce diagnostics and failure status,
even after an earlier `find-all` hit. A `sed` engine error terminates the
command while an input producer is still open. These bounds apply per engine match,
not to the total size of input, output, or a stream with arbitrarily many lines.

`grep` preserves the existing behavior of skipping invalid UTF lines; `-b`
searches them as bytes. Its literal ASCII path and buffered regular-file output
remain in place, while pipes/FIFOs deliver lines immediately. File open/read
errors and failed writes return failure. `sed` preserves an unterminated last
line and uses a new owned stream for redirected stdin on every call. Completed
file streams do not persist across calls. Every output command checks flush
errors and clears stdout's error state for the next builtin.

## Reproduction

All compilation must use the campaign build gate and all measurements or
profiling must use the bench gate. The Python correctness test never compiles.

```sh
python3 tests/sol-pcre-check.py out/bash-sol-pcre
python3 tests/pcre-streams.py out/bash-sol-pcre
python3 tests/pattern-fastpaths.py out/bash-sol-pcre
# Build the reference/profiler separately through the build gate:
cc -O2 tests/sol-pcre-reference.c -lpcre2-8 -o "$BASHOS_TASK_DIR/reference"
cc -O2 -fPIC -shared tests/sol-pcre-profile.c -ldl -o "$BASHOS_TASK_DIR/profile.so"
# Run through the bench gate:
python3 bench/sol-pcre.py --binary out/bash-sol-pcre \
  --reference "$BASHOS_TASK_DIR/reference" \
  --profiler "$BASHOS_TASK_DIR/profile.so" --output "$BASHOS_TASK_DIR/after.json"
```

The focused test uses an independent libpcre2 capture oracle and exact expected
bytes for replacements and empty matches. It checks binary/UTF input, invalid
patterns/options, sparse captures, readonly binding, cache eviction, output
failure recovery, adversarial limits, and 1,000 repeated stream/cache cycles
with descriptor counts, plus a 10,000-cycle memory checkpoint bounded to an
8 MiB RSS increase. The sanitizer build script instruments the actual
production source. With `SOL_PCRE_LOAD_ENV` it also exercises 40 unload/reload
cycles. Existing helper-smoke PCRE assertions and stream/fastpath assertions
are retained.

The benchmark reproduces the catalog's seeded 423,000-byte text and its exact
`pcre grep alpha text` operation, 14 passes per batch. Every batch's complete
stdout and status are checked against independently selected records. GNU
`grep -P` and the task-owned PCRE2 C reference process the identical fixture;
the latter explicitly uses UTF/UCP and the same match/depth limits. Each
variant gets a warmup and seven samples with alternating order on the recorded
CPU affinity. Reports include all samples, fixture/source/binary hashes,
versions, environment, work counts, and PCRE2 API call counts. API microbatches
have fixed independent assertions and carry no external performance ratio.

## Historical result investigation

The September 12 snapshot recorded 66.335 ms versus 15.711 ms for GNU grep
(4.2222 times external batch time). Commit `4e900eb2e3816c585f4432365cc537e884b5b862`
on September 14 subsequently introduced PCRE's literal ASCII block reader,
64 KiB output batching, and per-command match context lookup. The assigned
starting source already contains those changes. Its exact catalog operation
therefore does not represent the earlier per-line regex/output path. The
historical timing is preserved; a cross-build or cross-host subtraction would
not establish a paired speedup. New reports distinguish this provenance from
the paired baseline/final binaries on the current host.

## Current measurements

Measured on an Intel Core i7-9850H, CPU 11, Bash 5.3.15, PCRE2 10.46.
The catalog fixture SHA-256 is
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`: 423,000
input bytes and 313,188 selected output bytes per pass. Seven samples follow a
warmup. Raw reports are preserved as `catalog-before.json`,
`catalog-final.json`, `api-before.json`, and `api-final.json` in the task's
evidence directory, outside historical datasets.

The unchanged catalog harness (stdout to `/dev/null`) measured 15.492 ms
builtin versus 17.346 ms GNU at baseline, and 14.895 versus 16.356 ms finally
(0.911 times GNU time). Both case statuses are `ok`. BusyBox rejects `-P`
with status 2 and has no valid timing or ratio. The historical 4.2222 ratio
therefore does not reproduce in the assigned source.

The separate output-capturing harness adds pipe delivery and full output
validation to every timed batch. Its final builtin median is 31.318 ms,
versus 74.023 ms for the matched PCRE2 C reference and 57.423 ms for GNU
(0.423 and 0.545 times reference time respectively). These ratios describe
the complete line-selection operation, including process startup and I/O.
The literal builtin fastpath performs no `pcre2_match` calls for this fixture;
it is not a measure of general regex engine throughput. Do not mix the two
harnesses' absolute times.

For 5,000-operation API batches (milliseconds):

| Workload | Baseline | Final | Compile / match-data allocations, baseline → final |
|---|---:|---:|---|
| Retained text with captures | 50.815 | 49.624 | 1 / 5,000 → 1 / 1 |
| Retained binary with conversions/captures | 57.320 | 55.495 | 5,000 / 5,000 → 1 / 1 |
| Unique-pattern compile/match/captures | 44.136 | 49.197 | 5,000 / 5,000 → 5,000 / 5,000 |
| Retained replacement | 58.205 | 65.687 | 1 / 5,000 → 1 / 1 |

The profiler verifies the allocation/recompile reductions, including binary
patterns containing NULs. Hex decoding and capture encoding still allocate
per call, and Bash argument expansion and capture binding remain part of the
work. Retained text and binary median times fell only 2.3% and 3.2%, with
overlapping sample ranges. Unique-pattern time rose 11.5% and replacement
time rose 12.9%; the final implementation also checks output errors and
strengthens resource limits. The runs do not isolate each added check's cost,
and support no uniform API latency speedup claim. Each workload has its own
fixed assertions; subtracting their times does not isolate compilation or
conversion cost. No external ratio is assigned to these API batches.

Final native and ASan/UBSan focused runs each passed 92 checks, including the
40 unload/reload cycles in the instrumented run. The existing stream suite
passed seven checks both natively and instrumented; the existing fastpath
suite passed 40 checks. Its non-PCRE grep/sed assertions use host commands in
the PCRE-only build. All four original helper-smoke PCRE assertions are also
executed by the focused driver. LeakSanitizer is disabled for the uninstrumented
Bash host; memory/descriptor checkpoints, exercised unloads, and ASan/UBSan
cover the command-owned lifetime paths. There is no hardware qualification
requirement or exported pattern-handle ABI in this scope.
