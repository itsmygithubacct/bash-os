# bench — bash-os against busybox and against bash with the GNU userland

`bench/run.sh` runs the same POSIX `sh` scripts under three userlands and
reports the median wall time and the number of processes each one created:

| userland | shell | `PATH` | what a command is |
|---|---|---|---|
| **bashos** | `out/bash` (or `--static` / `--binary BIN`) | empty | a builtin of the shell: no fork, no exec |
| **busybox** | `busybox sh` (ash) | a directory of applet links | a fork, and an exec of one multi-call binary |
| **gnu** | `/bin/bash` | the system's | a fork and an exec of a separate GNU binary |

```
./build.sh && ./build.sh --static
bench/run.sh                    # 5 timed runs per cell, median
bench/run.sh --static           # bench the static binary
bench/run.sh --quick            # one run, small data: what tests/run.sh does
bench/run.sh --binary out/bash-core
STRACE=/path/to/strace bench/run.sh # exact descendant counts, measured separately
python3 bench/profiles.py --cpu 0 out/bash-shell out/bash-core out/bash
bench/run.sh --busybox /path/to/busybox --only tree
```

## Method

- Every workload is one script in `bench/workloads/`, POSIX `sh`, run as
  `SHELL script DATA SHELL N` — never through a shebang — so each userland's
  own shell runs the same text. Each prints a small result, and the harness
  checks the three results agree (a `*` marks a workload where they do not).
- One warm-up run, then `--runs` timed runs; userland order reverses on
  alternate rounds. The median wall time is reported. Timing is the host
  Bash's `time` around the whole script, without tracing.
- With `strace` on `PATH` or supplied by `STRACE`, **procs** counts successful
  fork/clone calls in a separate run, excluding the initial shell. It includes
  child threads if any are created. Without a tracer, the labeled fallback is
  the kernel's system-wide last-PID counter, which includes the harness and
  unrelated activity; those fallback counts require a quiet host.
- Data is generated once per run with a fixed seed: a 423 KB text of words,
  an 89 KB log, 1000 small files. Workload 04 builds its own tree.
- The footprint line is bytes on disk for the shell plus the commands the
  workloads use, resolved on that userland's `PATH`. Shared libraries are not
  counted, so a dynamically linked busybox or bash needs libc on top.

## Text-tool update, 2026-09-07

The four text-tool changes were compared in the same Bash 5.3.15 executable:
the earlier builtin versus the replacement loaded with `enable -f`. Shared
objects used `-O2 -fPIC -shared -Wl,-Bsymbolic` so calls bind to the replacement.
The host was an Intel Core i7-9850H, Linux 6.12.96, with processes pinned to one
CPU. Each cell is the median of five runs after a warm-up, with old/new/GNU
order reversed on alternate runs. Output went to `/dev/null`; timings include
the loop and shell startup. GNU commands were `/usr/bin` coreutils 9.7 and
grep 3.11, invoked from Bash 5.2.

| workload | earlier builtin ms | replacement ms | GNU ms | speedup over earlier builtin |
|---|---:|---:|---:|---:|
| `cut -d ' ' -f1`, 423,000 bytes, 100 passes | 683.30 | 49.41 | 229.59 | 13.8× |
| `grep -c the`, same input, 100 passes | 244.95 | 71.69 | 82.18 | 3.4× |
| `sort -n`, 50,000 signed integers, 10 passes | 986.28 | 126.47 | 227.67 | 7.8× |
| `seq 100000`, 30 passes | 888.20 | 35.20 | 39.01 | 25.2× |

Inputs used Python's random seed 20260906: ten words per line drawn from
`the and of to in is for that with a`, truncated to 423,000 bytes, followed by
50,000 integers drawn from `[-1000000, 1000000)`. These measurements isolate
each tool; they do not update the full-workload timings or footprint below.

## Buffered output, 2026-09-07

`paste` and `uniq` now use a 64 KiB output buffer instead of flushing Bash's
line-buffered stdout for each record. A native run checked 699 GNU parity and
shell-state cases, repeated under ASan/UBSan. The cases include embedded NULs,
records around the buffer boundary, grouping, repeated invocations and write
failures. Terminal output still flushes complete lines while input remains open.
A failed output write now returns failure.

| workload, ten passes | earlier builtin ms | buffered builtin ms | GNU ms | speedup |
|---|---:|---:|---:|---:|
| `paste`, 120,000 records | 417.39 | 68.26 | 62.02 | 6.1× |
| `uniq`, 40,000 groups of three records | 201.58 | 65.85 | 88.74 | 3.1× |

Input record `n` is `f"{n//3:08d} word\n"`, for `n` in `[0, 120000)`.
Both implementations ran in the same Bash 5.3.15 executable; the replacement
was loaded with `enable -f` and compiled with `-O2 -fPIC -shared -Wl,-Bsymbolic`.
Output went to `/dev/null`. Five timed runs followed a warm-up, reversing
old/new/GNU order each round, pinned to one CPU on the i7-9850H. Other work was
active on the host, so these comparisons support the buffering change but are
not isolated maximum-throughput measurements.

## Profile footprint

`bench/profiles.py` measures on-disk bytes, interleaved warm `:` startup, and
idle RSS/PSS after a shell signals that initialization is complete. Startup
includes the launch and wait overhead. Idle memory does not exercise the
selected helpers; workloads can allocate substantially more memory. PSS also
depends on which other processes share the executable and its libraries.

The earlier full-workload tables are retained in Git history. Use the commands
above to measure a selected profile on its intended host.
