# bench — bash-os against busybox and against bash with the GNU userland

`bench/run.sh` runs the same POSIX `sh` scripts under three userlands and
reports the median wall time and the number of processes each one created:

| userland | shell | `PATH` | what a command is |
|---|---|---|---|
| **bashos** | `out/bash` (or `out/bash-static` with `--static`) | empty | a builtin of the shell: no fork, no exec |
| **busybox** | `busybox sh` (ash) | a directory of applet links | a fork, and an exec of one multi-call binary |
| **gnu** | `/bin/bash` | the system's | a fork and an exec of a separate GNU binary |

```
./build.sh && ./build.sh --static
bench/run.sh                    # 5 timed runs per cell, median
bench/run.sh --static           # bench the static binary
bench/run.sh --quick            # one run, small data: what tests/run.sh does
bench/run.sh --busybox /path/to/busybox --only tree
```

## Method

- Every workload is one script in `bench/workloads/`, POSIX `sh`, run as
  `SHELL script DATA SHELL N` — never through a shebang — so each userland's
  own shell runs the same text. Each prints a small result, and the harness
  checks the three results agree (a `*` marks a workload where they do not).
- One warm-up run, then `--runs` timed runs; the median of the wall time is
  reported. Timing is the host bash's `time` around the whole script.
- **procs** is the kernel's last-PID counter before and after the run: every
  process created on the machine meanwhile, so it includes a constant handful
  of the harness's own and anything else running. Use a quiet machine.
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

## Earlier full-workload results

Host: Intel(R) Core(TM) i3-3220 CPU @ 3.30GHz, x86-64, kernel 6.12.94+deb13-amd64, 2026-09-06.
bash-os 5.3.10(1)-release; busybox v1.37.0 (Debian, dynamic); GNU: bash 5.2.37(1)-release, coreutils 9.7. Five timed runs per cell.

Measured on an idle machine (load below 3 on four cores throughout), which the
`procs` column requires. Earlier revisions of this page were taken on a busier
six-core i7-9850H; those numbers are in the git history, and the ratios, not
the milliseconds, are what carry across a host.

### `out/bash-static`

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        52 |      2154 |      2428 |   41.42x |   46.69x | 2/2020/2027        |
| 02-subst-per-file          |       444 |      1075 |      1949 |    2.42x |    4.39x | 1009/1011/2019     |
| 03-text-pipeline           |      2435 |      1446 |      1745 |    0.59x |    0.72x | 166/154/158        |
| 04-file-tree               |        79 |      1163 |      1162 |   14.72x |   14.71x | 9/1072/1072        |
| 05-wc-tail                 |       375 |      1132 |       576 |    3.02x |    1.54x | 3/411/409          |
| 06-sysinfo                 |       222 |       693 |       927 |    3.12x |    4.18x | 202/551/550        |
| 07-shell-startup           |       121 |       107 |       155 |    0.88x |    1.28x | 102/102/103        |
| 08-subst-nofork            |        76 |       n/a |       n/a |        - |        - | 2/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
| bashos: out/bash-static (statically linked) | 3669560 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

### `out/bash` (dynamic)

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        55 |      2185 |      2474 |   39.73x |   44.98x | 2/2019/2026        |
| 02-subst-per-file          |       625 |      1081 |      1980 |    1.73x |    3.17x | 1009/1011/2019     |
| 03-text-pipeline           |      2505 |      1441 |      1730 |    0.58x |    0.69x | 160/152/158        |
| 04-file-tree               |        81 |      1153 |      1159 |   14.23x |   14.31x | 8/1073/1072        |
| 05-wc-tail                 |       377 |      1133 |       579 |    3.01x |    1.54x | 3/410/409          |
| 06-sysinfo                 |       245 |       682 |       912 |    2.78x |    3.72x | 203/550/550        |
| 07-shell-startup           |       191 |       109 |       160 |    0.57x |    0.84x | 103/102/103        |
| 08-subst-nofork            |        76 |       n/a |       n/a |        - |        - | 2/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
| bashos: out/bash (dynamically linked) | 2265344 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

## Reading the earlier results

- **A tool per file** (01, 04): the whole point. Where a script calls a small
  command in a loop — a `wc` per file, a `mkdir`/`touch`/`cp` per entry —
  bash-os is 15 to 50 times faster, because those are 2 processes instead of
  2000. The `procs` column is the mechanism, not a side effect.
- **Capturing output** (02 vs 08): `$(...)` forks a subshell in every shell,
  bash-os included, so it is "only" 2 to 4 times faster there — the fork
  remains, the exec is gone. bash 5.3's `${ cmd; }` runs the builtin in the
  calling process: workload 08 is 02 rewritten that way, and it is as fast
  as 01. That is the bash-os idiom for scripts that read a command's output.
- **Long pipelines** (03): no win, and a loss. A pipeline forks its stages
  everywhere, and once the fork is paid the tools' own throughput decides:
  bash-os's `sort`, `tr` and `cut` are faster than GNU's, its `grep` and
  `uniq` are two to three times slower on this input. Those two are the
  follow-up, and they are why this row is still a loss: `cut`'s rewrite took
  its own stage from 168 ms to 12 ms per pass over the 423 KB file (GNU's is
  32 ms), and the whole row moved only from 2707 ms to 2502 ms — 7%, the
  median of six old/new runs interleaved so load drift hits both alike, with
  every new run faster than every old one.
- **wc and tail** (05): 3 times busybox and 1.5 times GNU, whose `wc` is
  vectorised and answers `-c` from `fstat`. The 3 processes are the
  harness's.
- **Shell start-up** (07): the price of the size. The dynamic `out/bash`
  starts slower than either (it is linked with full RELRO, so every
  relocation is resolved at start); the static binary is within 15% of
  busybox and ahead of bash. On a device, ship the static one.
- **Footprint**: one static file of 3.7 MB that needs nothing else, against a
  0.8 MB busybox that needs a libc, against 3.9 MB of GNU binaries that need
  several libraries.
