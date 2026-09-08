# expand: behavior and performance

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
tab values must fit a positive `int`, avoiding truncation of oversized options.

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

BusyBox 1.37.0 accepts uniform intervals but lacks explicit lists and `/N`.
It differs on binary input, backspaces and unterminated file continuation, so
those cases use GNU as the reference. Existing option limits remain: at most
64 explicit stops, positive extension sizes (GNU also accepts zero), no GNU
long-option abbreviations or `--version`, and successive `-t` options replace
rather than append stops. This is byte-column behavior, not Unicode display
width processing. These tests do not establish complete GNU CLI conformance.

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
