# expand: behavior and performance

Stdin duplication reserves descriptors 0–2, so closed stdout cannot become a writable alias of stdin. `tests/review-expand-descriptors.py` checks failure status, unchanged input and descriptor cleanup.

The measurements below predate this review correction. They describe the original
worker implementation; they are not measurements of the corrected code. No new
performance claim is made for this correction.

`expand [-i] [-t TABLIST] [FILE...]` converts tabs to spaces. The default
interval is eight columns. `TABLIST` accepts a positive interval or an
increasing comma/space-separated list. A final `/N` repeats at multiples of N;
`+N` repeats relative to the last explicit stop. After a finite list, each
remaining tab becomes one space. `-i` converts only initial blanks.

Files form one byte stream: the column and initial-blank state continue across
unterminated file boundaries. Newline resets both, backspace decrements a
positive column, and backspace also ends the initial blanks for `-i`. NUL and
other bytes survive unchanged. `-` reads stdin, and repeated calls start with
fresh options and column state. Read, open, close and output failures return
failure; invalid options return Bash's usage status 2.

## Implementation

The output loop uses a local 16 KiB buffer and fills padding with `memset`.
It sends blocks through `fwrite`, leaving Bash's stdout buffering untouched.
Terminal output flushes at newlines, including while the input remains open.
For redirected output, a partial block waits until it fills or the command
finishes. Input uses `getc_unlocked` where available, otherwise `fgetc`.
Memory use stays bounded independently of record length and tab width.

Stdin has a private `FILE` buffer over a duplicated descriptor, reused for
each `-` during the invocation and closed afterward. This prevents unread
bytes left by an output failure from appearing after a later shell redirection.
It requires one spare descriptor. Columns use checked `uintmax_t` arithmetic;
tab values use checked arithmetic up to `PTRDIFF_MAX`, avoiding truncation of
oversized options. Explicit stops use a dynamically allocated per-invocation list
that is freed on success and on option failure.

The change also corrects three existing GNU parity gaps: file continuation,
backspace with `-i`, and a single stop followed by separators (`-t '8,'`).
The previous implementation ignored read/write failures.

## Validation

```sh
JOBS=2 ./build.sh --profile core --no-strip
python3 tests/expand-parity.py out/bash-core
python3 tests/profile-smoke.py out/bash-core
```

The focused suite passed 263 GNU comparisons, 37 BusyBox comparisons and
14 state/error checks, also with the expand module under ASan/UBSan. It covers
empty/unterminated input, NULs and all byte values, explicit and extended stops,
input/output boundaries, a 1.2 MB record, padding across several output blocks,
multiple files/stdin, repeated redirections, missing files, directories,
closed descriptors, `/dev/full`, an ignored SIGPIPE, descriptor/state stability
and terminal delivery before EOF.

For the sanitizer run, build a module against this worktree's configured
headers and load it into the core binary:

```sh
bt=build/bash-5.3
gcc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$bt" -I"$bt/include" -I"$bt/builtins" \
  -I"$bt/examples/loadables" loadables/expand.c -o out/expand-sanitize.so
EXPAND_MODULE="$PWD/out/expand-sanitize.so" \
  EXPAND_PRELOAD="$(gcc -print-file-name=libasan.so)" \
  python3 tests/expand-parity.py out/bash-core
```

BusyBox accepts uniform intervals but lacks explicit lists and `/N`.
It differs on binary input, backspaces and unterminated file continuation, so
those cases use GNU as the reference.

## Option and locale completion

Repeated `-t`/`--tabs`/numeric shorthand options append stops. For example,
`-t3 -t7` is the finite list `3,7`, while `-t3 -t7 -t+4` repeats every four
columns after seven. An empty list adds nothing. Zero `/0` and `+0` extensions
are inert: `3,/0` is the single interval three, and `/0` alone uses eight.
Nonzero `/N` and `+N` are mutually exclusive. Within one argument the prefix
continues across separators, so `3,/8,12` is invalid; a separate `-t12` appends
an explicit stop. These rules match GNU coreutils 9.7, including repeated
extensions and its final-stop grammar. Lists grow beyond the former 64-stop
cap; individual values may reach `PTRDIFF_MAX` (on the qualified 64-bit build,
9223372036854775807). Parsing never emits padding. Values or column arithmetic
outside their checked range fail rather than wrap.

Short clusters and attached arguments work, unambiguous long-option prefixes
are accepted, and options may follow filenames. `--` ends option parsing;
`POSIXLY_CORRECT` stops parsing at the first operand. `--help` prints builtin
help and `--version` identifies the Bash-OS builtin and running Bash version. Help/version text and
invalid-option diagnostics are native to Bash-OS; usage failures return 2.

Columns count **bytes**, matching host GNU coreutils 9.7 in `C`, `C.utf8`, and
`en_US.utf8`. This deliberately does not implement Unicode display-width
alignment. At a default tab after `é`, the two UTF-8 bytes cause six spaces:
`X` reaches byte column eight and display column seven. After `界`, three bytes
cause five spaces: byte column eight, display column seven. After `e` plus
U+0301, three bytes cause five spaces: byte column eight, display column six.
Invalid UTF-8 survives exactly and consumes one column per byte. NUL, CR, FF,
VT, escape and other control bytes likewise count as one, with only BS and LF
special as described above. No decoding state crosses buffers, files, locales,
or invocations. Later GNU releases may adopt different locale behavior; they
are not the reference for this byte-column contract.

`tests/sol-expand-options.py` supplies explicit padding and UTF-8 display-cell
oracles, invalid-sequence/refill/file-boundary cases, generated repeated lists,
option errors and recovery, pipelines, and persistent locale changes. The display
model ignores C0/DEL controls except BS (back up) and CR/LF (reset), and counts
each invalid UTF-8 byte as one replacement cell; actual terminal rendering of
controls and invalid bytes is not claimed. Existing
`tests/expand-parity.py` assertions remain, with the old intentional-limit
rejections replaced by GNU success comparisons. `tests/expand-sanitize.sh`
runs both suites with the production module instrumented by ASan/UBSan.

## Measurements, 2026-09-08

Both binaries use the native dynamic core profile, Bash 5.3.15, GCC 14.2 and
`-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, with symbols retained.
The baseline is `ef66d799c99812f3132461cea7f00c983c45c98d`. SHA-256:

- Before: `1be8e32d620b249ce2a3273c79f58231b80b5448904eea7f813c59a7c653d18c`
- After: `69d14724abba194fc79ebb51bf591430f50452d1c65fba2631f70c9b50acc8f6`

The workload is `alpha\tbeta\tgamma\n` repeated, `expand -t 8`, ten
invocations per batch and seven untraced samples after single-call and complete
batch output validation. Every implementation in every reported run passed.
The 340,000-byte fixture SHA-256 is
`74d1f666fd82d6efeabf216977af7ff24937cedf2d5eceeec89112066c529a9a`.

On an Intel Core i7-9850H with Linux 6.12.96, all timed processes were pinned to
CPU 11. Timed runs held a shared advisory lock. Other host work continued:
one-minute load averages were 10.5–11.7 during the final paired runs. Each cell
below is median **milliseconds per ten-call batch**, followed by min–max.
References are GNU coreutils 9.7 and Debian BusyBox 1.37.0. Both reference
measurements are shown because the host was contended.

| Input bytes | Builtin before | Builtin after | BusyBox before / after | GNU before / after |
|---:|---:|---:|---|---|
| 340 | 4.182 (3.031–5.012) | 4.025 (2.933–4.669) | 17.355 (14.924–21.399) / 19.836 (12.796–21.465) | 14.766 (12.455–19.688) / 17.123 (11.611–19.443) |
| 34,000 | 16.814 (11.395–22.589) | 7.130 (5.332–9.528) | 26.723 (21.752–29.343) / 28.922 (23.942–44.943) | 17.861 (12.177–23.048) / 18.101 (14.635–27.652) |
| 340,000 | 113.047 (100.620–142.849) | 26.461 (23.656–34.662) | 120.918 (99.984–140.198) / 132.799 (123.062–154.432) | 34.595 (29.550–37.611) / 35.897 (27.536–44.342) |
| 3,400,000 | 1116.641 (1063.827–1165.033) | 207.529 (193.474–243.909) | 1047.698 (961.745–1118.472) / 958.658 (922.062–1067.338) | 202.511 (183.258–228.784) / 193.388 (175.678–215.573) |

The target fixture improved 4.27× in these paired runs; the larger fixture
improved 5.38×. The smallest input supports no improvement claim. GNU remains
competitive on the largest fixture. Timings include shell startup, redirection
and external fork/exec costs, with output to `/dev/null`; they are not isolated
algorithm throughput or device measurements.

The first baseline reproduction, at load 6.1, measured 72.169 ms
(69.677–80.401), BusyBox 74.865 (71.140–92.089), and GNU 20.921
(19.815–29.237). This is consistent with the historical review's 70.836 /
70.702 / 23.479 ms. The paired table above uses a fresh baseline alongside
the changed binary, rather than combining runs under different loads.

A userspace SIGPROF probe over 1,000 target invocations collected 2,018 samples:
11.1% in libc input, 22.9% in output overflow functions, 18.2% in `bx_process`,
and 43.0% in libc code without exported symbols, mostly a syscall wrapper.
Kernel perf events were unavailable. A separate syscall trace of one invocation
confirmed **20,000 → 132 stdout writes**, with identical 440,000 output bytes.
The same sampling probe after the change collected 371 samples, 84.1% in
`bx_process`: transformation now dominates. Profiling and tracing were separate
from all reported timings.

Reproduce using the existing harness and the command-specific size adapter:

```sh
# Select an allowed CPU and a lock shared with other benchmark jobs.
lock=/tmp/bash-os-loadable-bench.lock
flock "$lock" python3 bench/loadables.py --only expand --passes 10 --runs 7 \
  --cpu 11 --binary out/bash-core --output /tmp/expand.json
flock "$lock" python3 bench/expand.py --lines 200000 --passes 10 --runs 7 \
  --cpu 11 --binary out/bash-core --output /tmp/expand-large.json
```

The size adapter changes only the `tabs` fixture and its recorded hash; timing,
validation, calling pattern and reference selection remain in `loadables.py`.
Use 20, 2,000 and 200,000 lines for the other sizes. Inspect every JSON result's
`status`: harness exit zero alone does not mean validation passed.

## Completion measurement protocol

The task-owned size sweep uses `bench/sol-expand.py`. It checks every output
byte and status in every warm-up and timed batch, including every repeated
invocation. Output goes to a private regular file; validation runs after the
timer. Batch timings include shell startup, a builtin identity probe, redirects,
and private-file output. The external reference uses the same selected shell.
These numbers must be labeled separately from historical `/dev/null`
timings. Its independent expected record is `alpha   beta    gamma\n`.
The 20,000-line catalog fixture uses 38 calls per batch; sizes of 20, 2,000,
and 200,000 lines qualify tiny, medium, and large inputs. Each cell has seven
samples after a full-batch warm-up. The gate fixes CPU affinity; implementation
order rotates and reverses. Reports record fixture hashes, work counts, binary
and source hashes, tool versions, environment, and sample distributions.

Build the targeted selection through the build gate, then run the strict sweep
through the bench gate. Its catalog-size cell uses the existing catalog work unit.
Required build companions for `tests/input-lifetime.py` are `head,sed,fold,nl,pr,tac,bc`;
`expand` itself needs no companion or shared helper. Run the sanitizer script
through the build gate because it compiles the production module. Normal
correctness scripts do not compile.

## Completion qualification, 2026-10-19

The targeted native build passed 282 GNU comparisons, 37 BusyBox comparisons,
eight state/error checks, and 351 independent option/byte/display checks.
The same 678 checks passed with the production expand module under ASan/UBSan.
All three tested locales (`C`, `C.utf8`, `en_US.utf8`) were available; none were
skipped. The mixed-reader suite passed 156 checks, and the two unchanged expand
comparisons extracted from the shared text-tool suite passed. The new repeated
`-t` regression fails against the baseline, confirming that it detects the gap.
The broader shared text-tool suite and full catalog remain integration checks.

Both native builds use the same eight-loadable selection, Bash 5.3.15 and
GCC 14.2.0, with `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2`, symbols
retained. No shared helper changed. Binary SHA-256:

- Baseline: `9e9637fa2cd0ea1869f4b1bb086e509daea413751b06dc49219bbea12a9d7b7f`
- Completed: `a32b5668d542258b6cd97ddce59e11b52ed2e3b6c0c92708ae2681d53c8312d7`

Primary-source SHA-256:

- Baseline (unchanged from the campaign source baseline):
  `3e74e5fc57fbbaba68560aa9c1e7a3702f46f2a7097622330f4606528a4b49d4`
- Completed:
  `82378e0307183c35728fea786f8c120e2a99e838450fe0b0b1f1d9c9a9774340`

The strict sweep ran on the i7-9850H, CPU 11, Linux 6.12.111, glibc 2.41,
with GNU coreutils 9.7. The paired run's one-minute load average moved from
7.44 to 7.23. Every warm-up and timed pass passed the byte and status oracle.
Each cell below is median **milliseconds per batch**, followed by min–max;
batch counts differ as shown. These are private regular-file output timings.

| input bytes | calls/batch | baseline ms | completed ms | GNU ms |
|---:|---:|---:|---:|---:|
| 340 | 38 | 3.877 (3.700–4.162) | 3.725 (3.653–5.076) | 32.038 (29.918–35.838) |
| 34,000 | 10 | 6.157 (5.954–6.482) | 6.031 (5.859–6.308) | 12.225 (11.132–14.245) |
| 340,000 | 38 | 89.151 (80.400–92.504) | 81.981 (76.232–99.677) | 113.728 (104.796–128.156) |
| 3,400,000 | 10 | 273.056 (242.222–346.530) | 247.506 (217.951–282.002) | 274.200 (224.443–295.519) |

The 340,000-byte row reproduces the catalog fixture/hash and `expand -t 8`
work count. An earlier baseline-only run independently validated all four sizes;
its baseline/GNU medians were 5.110/49.944, 9.015/18.339, 131.361/171.448,
and 328.693/348.393 ms. It is retained separately from the paired run, because
host conditions changed. The completed builtin's tiny-input advantage over GNU
is established for this 38-call workload; the before/after implementation
ranges overlap and do not establish a tiny-input improvement from these changes.
The large-input ranges also overlap. No reproducible remaining slowdown
motivated a transformation/output-loop optimization, so that loop was retained.

Reproduce through the resource gate with the strict adapter (no build occurs):

```sh
python3 bench/sol-expand.py --binary before=out/bash-sol-expand-before \
  --binary after=out/bash-sol-expand-after \
  --source-for before=/path/to/baseline-expand.c \
  --source-for after=loadables/expand.c --runs 7 --output /tmp/expand-paired.json
```

The report preserves all seven samples, source/binary/reference hashes,
versions, environment, affinity, fixture hashes, work counts and validation
statuses. Native x86-64 glibc is qualified here; these new changes were not
rerun under RISC-V/musl. Historical cross-libc evidence remains separate.
