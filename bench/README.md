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

## Results

Host: Intel(R) Core(TM) i7-9850H CPU @ 2.60GHz, x86-64, kernel 6.12.96+deb13-amd64, 2026-09-06.
bash-os 5.3.10(1)-release; busybox v1.37.0 (Debian, dynamic); GNU: bash 5.2.37(1)-release, coreutils 9.7. Five timed runs per cell.

### `out/bash-static`

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        29 |      1384 |      1491 |   47.72x |   51.41x | 2/2005/2009        |
| 02-subst-per-file          |       273 |       699 |      1189 |    2.56x |    4.36x | 1003/1003/2005     |
| 03-text-pipeline           |      1489 |      1022 |      1205 |    0.69x |    0.81x | 152/145/144        |
| 04-file-tree               |        38 |       745 |       725 |   19.61x |   19.08x | 8/1065/1065        |
| 05-wc-tail                 |       336 |       820 |       337 |    2.44x |    1.00x | 3/404/403          |
| 06-sysinfo                 |       213 |       484 |       724 |    2.27x |    3.40x | 202/543/544        |
| 07-shell-startup           |        81 |        75 |       110 |    0.93x |    1.36x | 102/102/102        |
| 08-subst-nofork            |        35 |       n/a |       n/a |        - |        - | 2/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
| bashos: out/bash-static (statically linked) | 3656888 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

### `out/bash` (dynamic)

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        28 |      1416 |      1519 |   50.57x |   54.25x | 2/2006/2027        |
| 02-subst-per-file          |       342 |       711 |      1188 |    2.08x |    3.47x | 1003/1003/2005     |
| 03-text-pipeline           |      1518 |      1017 |      1251 |    0.67x |    0.82x | 161/144/146        |
| 04-file-tree               |        38 |       794 |       840 |   20.89x |   22.11x | 8/1065/1065        |
| 05-wc-tail                 |       346 |       822 |       339 |    2.38x |    0.98x | 3/404/403          |
| 06-sysinfo                 |       215 |       484 |       732 |    2.25x |    3.40x | 202/543/543        |
| 07-shell-startup           |       121 |        71 |       112 |    0.59x |    0.93x | 103/102/102        |
| 08-subst-nofork            |        40 |       n/a |       n/a |        - |        - | 2/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
| bashos: out/bash (dynamically linked) | 2252672 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

## Reading it

- **A tool per file** (01, 04): the whole point. Where a script calls a small
  command in a loop — a `wc` per file, a `mkdir`/`touch`/`cp` per entry —
  bash-os is 20 to 50 times faster, because those are 2 processes instead of
  2000. The `procs` column is the mechanism, not a side effect.
- **Capturing output** (02 vs 08): `$(...)` forks a subshell in every shell,
  bash-os included, so it is "only" 2 to 4 times faster there — the fork
  remains, the exec is gone. bash 5.3's `${ cmd; }` runs the builtin in the
  calling process: workload 08 is 02 rewritten that way, and it is as fast
  as 01. That is the bash-os idiom for scripts that read a command's output.
- **Long pipelines** (03): no win, and a loss. A pipeline forks its stages
  everywhere, and once the fork is paid the tools' own throughput decides:
  bash-os's `sort` and `tr` are faster than GNU's, its `grep`, `cut` and
  `uniq` are two to three times slower on this input. Those three are the
  follow-up.
- **wc and tail** (05): 2.4 times busybox and level with GNU, whose `wc` is
  vectorised. The 3 processes are the harness's.
- **Shell start-up** (07): the price of the size. The dynamic `out/bash`
  starts slower than either (it is linked with full RELRO, so every
  relocation is resolved at start); the static binary is within 10% of
  busybox and ahead of bash. On a device, ship the static one.
- **Footprint**: one static file of 3.7 MB that needs nothing else, against a
  0.8 MB busybox that needs a libc, against 3.9 MB of GNU binaries that need
  several libraries.
