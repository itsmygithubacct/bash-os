# Fold behavior and performance

`fold` is included in the core profile and its supersets. It wraps at 80
display columns by default; `-w WIDTH` selects a positive width up to
2,147,483,647. `-b` counts bytes, `-c` counts decoded characters, and `-s`
breaks after the last space or tab before the wrap. The last `-b` or `-c`
option selects the counting mode. Files are processed in order; no file or
`-` reads stdin. Column state resets for each file, even when the previous
file has no final newline.

## Implementation

Printable ASCII runs that fit the current width are copied together. Tabs,
backspaces, carriage returns, other controls, non-ASCII bytes and wrap
boundaries use the general decoder and column logic. The `-s` remainder is
still rescanned after a wrap. Printable ASCII also bypasses `wcwidth` in
that remainder path.

Output uses the existing per-invocation 64 KiB buffer in
[`bl-output.h`](../loadables/common/bl-output.h). It flushes complete lines
to a terminal and flushes remaining bytes before returning. It does not
change Bash's stdout buffering. Write errors return failure and stop further
input processing once detected. Stdin has a private stdio stream on a
duplicated descriptor, shared by repeated `-` operands within one call and
closed afterward. This prevents EOF/error flags and prefetched bytes left
by an output failure from contaminating the next redirected invocation.

Pending-line storage grows on demand, starting at no more than 4 KiB even
for a very large width. Column arithmetic can represent a tab or wide
character beyond the maximum accepted width. Byte offsets and allocation
growth use `size_t` with overflow checks.

## Compatibility boundaries

The focused checks use GNU coreutils 9.7 and Debian BusyBox 1.37.0. These
references do **not** implement the same complete interface:

| Behavior | bash-os fold | GNU 9.7 | BusyBox 1.37.0 |
| --- | --- | --- | --- |
| `-b`, `-s`, `-w N`, `-wN` | supported | supported | supported |
| `-N` width shorthand | supported | supported | supported |
| Combined `-sN` | supported | supported | rejected |
| `--width`, `--bytes`, `--spaces` | supported | supported | rejected |
| `-c`, `--characters` | supported | rejected | rejected |
| `-w +3` | accepted | accepted | rejected |
| Maximum accepted width | 2,147,483,647 | accepts that width | 10,000 |

In column and character modes, tabs advance to the next multiple of eight,
backspace subtracts the last character's width, and carriage return resets
the column. These controls count as one byte under `-b`. Only ASCII space
and tab are word-wrap opportunities. NUL is preserved: it has display width
zero in column mode and counts as one in byte/character modes.

The existing decoder groups UTF-8 sequences even in the C locale. Column
mode uses the active locale's `wcwidth`; character mode counts each decoded
unit once. GNU 9.7's fold splits UTF-8 bytes in both tested locales. BusyBox's
UTF-8 behavior also differs from the builtin's display-width rules. Therefore
the tests compare Unicode output with explicit builtin contracts, and use
byte mode for binary/Unicode comparisons with both references.

Malformed input retains the prior behavior. Missing continuations and
incomplete sequences fall back to individual bytes. The decoder is
permissive: it also groups overlong encodings, surrogate encodings and
out-of-range code points. This change does not make it a strict UTF-8
validator. Tests preserve those outputs, including embedded NULs.

Input still uses an 8 KiB `fread` lookahead. A short line on a pipe or terminal
can wait for more input or EOF; the terminal tests feed a complete input
block and require output before EOF. Output buffering preserves that
existing behavior. Records containing many carriage returns, backspaces or
zero-width characters can require storage proportional to their byte length.

## Validation

```sh
JOBS=2 ./build.sh --profile core --no-strip
python3 tests/profile-smoke.py out/bash-core
python3 tests/fold-parity.py out/bash-core
bash tests/fold-sanitize.sh out/bash-core
```

The native and ASan/UBSan runs each passed 2,651 checks in C and C.UTF-8.
The suite covers wrap edges, options and reference differences, tab/BS/CR,
Unicode widths, malformed/incomplete bytes, NULs, empty and unterminated
input, input/output buffer boundaries, long records, multiple files,
repeated redirected calls, descriptor lifetime, reads after failures,
`/dev/full`, closed output, an ignored SIGPIPE, output order and terminal
flushing. The sanitizer module compiles the repository source and loads it
into a real Bash process; Bash-wide leak detection is disabled.

A separate deterministic comparison with the saved baseline passed 500
mixed-byte cases across all six combinations of counting/space modes in
both locales. These comparisons establish preservation for the exercised
cases, not complete GNU or BusyBox conformance.

## Measurements, 2026-09-08

The baseline is `ef66d799c99812f3132461cea7f00c983c45c98d`, including its
later GPU changes; fold itself was unchanged from the historical benchmark
review. Both binaries are native dynamic core builds, Bash 5.3.15, GCC 14.2,
with `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2` and `--no-strip`.
The host was an Intel Core i7-9850H running Linux 6.12.96 on x86-64. All timed
runs held the shared advisory benchmark lock and pinned the harness and
children to CPU 11.

The initial reproduction measured **80.350 ms** (76.559–89.581) for the
builtin, **37.890 ms** (33.645–52.177) for BusyBox, and **23.724 ms**
(21.829–47.223) for GNU. All single-call and nine-call output checks passed.

Hardware `perf` sampling was unavailable under the host's permissions. A
separate SIGPROF program-counter sampler ran the actual builtin from Bash:
3,881 baseline samples placed 26.5% in `wcwidth`, 23.5% in the fold stream
loop, 9.7% in column advancement, and 4.4% in decoding. A further 26.5%
landed at a libc syscall return instruction. After output buffering and
the width-one shortcut, 2,050 samples placed 66.6% in the stream loop,
18.6% in column advancement and 7.2% in decoding. This motivated the ASCII
span path. These profiles are diagnostic samples, not timed benchmark runs.

The final before/after comparison below used
[`bench/loadables.py`](../bench/loadables.py), with seven timed samples and
nine invocations per sample. The harness checks one call and an entire
redirected-input batch before timing. Every reported result had JSON
status `ok`. Each row shows **median milliseconds (minimum–maximum)**.

| Input bytes | Build | fold | BusyBox | GNU |
| ---: | --- | ---: | ---: | ---: |
| 4,096 | before | 3.051 (2.972–4.241) | 8.274 (7.996–13.389) | 7.464 (6.812–8.708) |
| 4,096 | after | 2.501 (2.274–2.787) | 8.682 (8.034–10.749) | 8.021 (7.004–8.412) |
| 42,300 | before | 11.517 (10.140–18.698) | 11.851 (11.159–13.742) | 9.093 (8.164–14.075) |
| 42,300 | after | 3.618 (3.178–4.990) | 13.131 (11.342–17.325) | 10.213 (8.553–12.691) |
| 423,000 | before | 87.639 (83.135–99.736) | 38.539 (36.771–44.145) | 25.900 (23.434–40.569) |
| 423,000 | after | 11.399 (10.122–16.968) | 37.806 (36.116–47.257) | 23.093 (21.932–25.650) |
| 4,230,000 | before | 931.601 (890.074–985.556) | 327.659 (300.818–349.329) | 190.246 (172.990–222.144) |
| 4,230,000 | after | 107.241 (104.285–129.396) | 312.960 (304.786–328.754) | 198.753 (185.273–221.189) |

The confirmed 423,000-byte case improved **7.69×** against the paired
baseline; after-change time was 0.49× GNU time and 0.30× BusyBox time.
The smaller fixture is increasingly dominated by shell startup and call
overhead. These ratios describe this ASCII workload and calling pattern;
they do not establish gains for Unicode, every option, terminal throughput,
static builds or other architectures.

Other work remained active on the host. The one-minute load average was
approximately 6.1–6.2 during the initial reproduction and 6.9–7.3 during
the final comparisons; five-minute load was about 8.7–8.9 during the latter.
The advisory lock excludes other participating timed runs, not unrelated
CPU, cache or frequency contention. Compare the medians with their ranges.

A separate `/proc/self/io` snapshot after the same nine calls recorded
144,623 total write syscalls before and 65 after, with identical output byte
counts. Those totals include the same small shell startup contribution.
They support the output-buffering explanation without using traced timings.

### Reproduction

Save the baseline binary before rebuilding, then run each build under the
same shared lock (choose an allowed CPU on another host):

```sh
flock "$BENCH_LOCK" python3 bench/loadables.py --only fold --passes 9 --runs 7 \
  --cpu 11 --binary "$BEFORE_BINARY" --output "$RESULTS/before.json"
flock "$BENCH_LOCK" python3 bench/loadables.py --only fold --passes 9 --runs 7 \
  --cpu 11 --binary out/bash-core --output "$RESULTS/after.json"
```

Inspect `cases[0].results` in both reports; harness exit zero alone is not
an output-validation verdict. The fixture is the harness's deterministic
seed-20260908 text, SHA-256
`fb6bb6eb8b1cfd98fb3003298131a665522fd5b2df04e7d9c7574a2dd63241ee`.
Size variations used its first 4,096 or 42,300 bytes, or ten concatenated
copies for 4,230,000 bytes. They used the same harness with only the `text`
fixture and its metadata replaced; flags, calling pattern and pass/sample
counts stayed identical. Raw reports, samples, profiler code and binaries
are retained outside Git for integration.

Binary SHA-256 values for these measurements:

```text
before 1be8e32d620b249ce2a3273c79f58231b80b5448904eea7f813c59a7c653d18c
after  766ee6c6a7b426301f5b014a2072f4372e1514ebf1549e0de572778a6d1b1f21
```
