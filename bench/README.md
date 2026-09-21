# bench — bash-os against busybox and against bash with the GNU userland

The [loadable status table](../docs/loadables-status.md) covers all 279 loadables
and recommends the next work from correctness checks and individual timings.
Its [CSV](../docs/loadables-status.csv) supports filtering by profile and status.
The current table uses one integrated full build and seven samples per case.
The [original measurement](../docs/data/loadable-benchmarks.json) and its
graphics data retain their separate source and binary provenance.
Completed input fixes receive timings only after the repeated-call output check passes.

## Individual commands

`bench/loadables.py` runs the builtin, the BusyBox applet and the external
program from the same bash-os shell, validates outputs across repeated
invocations, then records batch wall time. Incorrect results are marked in JSON
and receive no builtin timing or ratio. The report continues after mismatches; a
successful harness exit does not mean every loadable passed. `--quick` still
checks at least three invocations. Digest comparisons preserve every output
record while ignoring the reference tool's filename field. Missing, changed,
extra or blank later records fail validation; `tests/bench-loadables.py`
exercises those failure paths. The `diff` case compares identical files and
measures no edit-script generation.

The four `git-*` cases work on one repository fixture: 2,000 tracked files
in 64 directories, 200 commits over them, an index carrying their stat data,
twenty files changed since it was written and five never added. Its
timestamps are set rather than taken from the clock, because an entry
written in the same second as the index can only be settled by reading the
file, and these cases measure the other path. `git-add` compares the index
both implementations write, byte for byte, rather than their (empty)
output.

`bench/git-scale.py [FILES] [COMMITS]` is the other half of the git
measurement: a repository of a few thousand files and a few thousand
commits, built from sha1 and zlib alone, with every command run through
both implementations for wall time and peak resident memory. A clone runs
over the protocol on both sides, since the local clone git is allowed to
hardlink measures nothing. It writes a few hundred megabytes into a
temporary directory, which is why it is a benchmark and not a test.

```sh
python3 bench/loadables.py --output /tmp/loadables.json
python3 bench/loadables.py --only fold --passes 9 --runs 7 --output /tmp/fold.json
python3 bench/loadables.py --quick --only head,sed,bc --output /tmp/input-check.json
python3 bench/catalog.py --check
```

### What a case can be

Each case is one `add()` call in `cases()`. By default it compares the builtin
with an external program and a BusyBox applet on the same fixture, in one shell
process, with the fixture redirected onto stdin for every pass. Four options
cover the loadables that default shape cannot measure:

| option | what it does | when it is the honest choice |
|---|---|---|
| `reference='self'` | Times the builtin alone. Pass 1 becomes its own expected output, so the repeated batch is a **determinism check**, and both reference columns print an em dash instead of a ratio. | No external program or applet implements the thing at all — the persistent-handle and terminal APIs. A self-timed figure is comparable with another run of the same case on the same host, and with nothing else. |
| `mode='fresh'` | Runs each pass in a subshell, so the fork gives it a private copy of the process. Costs one fork per pass on every implementation being compared. | A command whose state is *meant* to persist between calls. Not a workaround for a reader that forgets to reset its stream — see below. |
| `reset='...'` | A snippet re-run before every pass, with the same empty `PATH`, so it must use builtins only. | A mutator that destroys its own precondition: `unlink`, `rmdir`, `mkfifo`, `link`, `mv`. |
| `env={...}` | Extra environment for every implementation in the case. | A fixture-root hook such as `BASHOS_PROC_ROOT`, which turns a live-counter tool into a fixed, deterministic workload. |

`work='...'` records the fixed work one pass does — bytes parsed, records
emitted, operations performed. It is documentation for the number, not an input
to it: a timing whose work is unstated cannot be compared across a change.

`mode='fresh'` deserves care. A builtin runs in the shell process, so its stdio
state outlives the call, and a reader that leaves stdin's EOF flag set will read
nothing on the *next* invocation while still exiting 0. That is a defect in the
loadable, not a property to be measured around — `clearerr` at entry is what the
stdin readers in this tree do, and `tests/repeat-input-check.sh` is the gate.
Reach for `fresh` only once you have established the in-process failure is
intended behaviour.

### Publishing a measurement

`bench/loadables.py` writes a raw report: everything the harness saw, including
failed validation. `bench/publish.py` turns that into the file the catalog is
allowed to describe. It strips every timing from a result that failed output
validation, records which comparison tools this host actually has, and refuses
to merge reports measured on different binaries.

```sh
flock /home/pleb/research/projects/bash-os/parallel-loadable-bench.lock \
  python3 bench/loadables.py --binary out/bash --runs 7 --cpu 11 --output /tmp/raw.json
python3 bench/publish.py /tmp/raw.json docs/data/loadable-benchmarks-current.json
python3 bench/catalog.py && python3 bench/catalog.py --check
```

Add `--merge` to keep cases measured earlier **on the same binary**; a different
binary is refused, because rows describing two executables cannot be compared
with each other. `--omit CASE --omit-reason '...'` drops a case that must not be
published, and records why — an undocumented gap reads as an oversight.

### The iteration loop

One loadable at a time:

1. Measure the current binary (`--only NAME`), keeping the raw JSON outside Git.
2. Change the implementation.
3. Rebuild with `JOBS=2 ./build.sh --include NAME --name NAME` for a
   single-loadable binary, or a full `./build.sh` before publishing.
4. Re-run the loadable's `tests/*-check.sh` against the new binary, with an
   empty `PATH`, comparing against GNU — or BusyBox where GNU is absent.
5. Re-measure `--only NAME` under the lock, on the same pinned CPU.
6. Publish and regenerate only when the output checks still pass.

A ratio is never published for output that does not match, and a corrected
invalid baseline is not a speedup. Both directions of that rule matter: a change
that makes a command faster and wrong has made the table worse, and a change
that makes a wrong command correct will often look like a regression.

Use `--cpu N` to pin to an allowed CPU, `--binary` to choose a build and
`--busybox` to choose a BusyBox binary. Inputs and writable destinations use a
temporary directory. See the table's [method](../docs/loadables-status.md#method-and-limits)
and [refresh instructions](../docs/loadables-status.md#refreshing-the-table).
`bench/catalog.py` regenerates the Markdown and CSV from the authoritative
catalog, profile resolver, reviewed coverage map and sanitized measurement JSON.
Keep raw run logs outside Git. Do not assign whole-script timings to individual
loadables or combine the historical measurements below with this new method.

The [tac update](../docs/tac.md) includes a nine-workload comparison of the
earlier and current builtin with GNU and BusyBox, plus correctness coverage
and remaining limits. Reproduce it with `python3 bench/tac.py --before OLD_BINARY
--after NEW_BINARY --cpu N --runs 7 --output /tmp/tac.json`; both binaries
must include `tac`. Keep the builds and CPU fixed and serialize timed runs.

The [zstd report](../docs/zstd.md) compares the builtin with host `zstd(1)` on
stdin compress and decompress. Frames are not byte-identical, so validation is
a GNU round-trip rather than an exact match. Reproduce it with
`python3 bench/zstd.py --binary out/bash --cpu N --runs 7 --output /tmp/zstd.json`.
The binary must include `zstd`. BusyBox has no applet in the Debian builds
this has been run against.

## Whole scripts

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

## Measurements, 2026-09-08

Intel Core i7-9850H, Linux 6.12.96, x86-64, GCC 14.2, Bash 5.3.15.
The profile measurements used 100 interleaved warm starts on one CPU and five
idle memory samples. Sizes exclude shared libraries. The RISC-V musl SDK build
of the full static profile is 10,416,736 bytes and passed the QEMU fixtures;
its timings are not compared with native execution.

| binary | injected | bytes | start ms | RSS KiB | PSS KiB |
|---|---:|---:|---:|---:|---:|
| bash-shell | 0 | 1364160 | 2.240 | 2988 | 1380 |
| bash-pure | 28 | 1447520 | 2.328 | 3076 | 1491 |
| bash-core | 89 | 2067616 | 2.421 | 3200 | 1639 |
| bash-device | 160 | 2734528 | 2.547 | 3752 | 1883 |
| bash-server | 214 | 6943104 | 2.972 | 4688 | 2531 |
| bash-desktop | 153 | 8103784 | 2.960 | 4564 | 2412 |
| bash | 278 | 11116104 | 3.158 | 5108 | 2959 |
| bash-device-static | 160 | 4101880 | 2.056 | 2712 | 2708 |
| bash-static | 278 | 13638056 | 2.328 | 3736 | 3728 |

The workload tables use five interleaved runs after a warm-up, pinned to one
CPU. Other work was active on the host, and the two profiles were measured in
separate runs; compare implementations within a table. Process counts come
from a separate `strace` pass and exclude the initial shell. Every workload's
output matched across the supported userlands.

The GNU footprint below covers the 28 external commands used by these scripts.
Each Bash profile includes its documented command selection; the full profile
also includes TLS, SSH, editors, databases, parsers and graphics.

### Core profile

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        41 |      2000 |      2627 |   48.78x |   64.07x | 0/2000/2000        |
| 02-subst-per-file          |       393 |      1015 |      1820 |    2.58x |    4.63x | 1000/1000/2000     |
| 03-text-pipeline           |      1336 |      1774 |      1020 |    1.33x |    0.76x | 140/140/140        |
| 04-file-tree               |        79 |      1730 |      2148 |   21.90x |   27.19x | 6/1061/1061        |
| 05-wc-tail                 |       621 |      1693 |      1070 |    2.73x |    1.72x | 0/400/400          |
| 06-sysinfo                 |       475 |      1184 |      1886 |    2.49x |    3.97x | 200/540/540        |
| 07-shell-startup           |       267 |       180 |       291 |    0.67x |    1.09x | 100/100/100        |
| 08-subst-nofork            |        70 |       n/a |       n/a |        - |        - | 0/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
|---|---|
| bashos: out/bash-core (dynamically linked) | 2067616 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

### Full static profile

| workload                   | bashos ms | busybox ms |    gnu ms |   bb/bos |  gnu/bos | procs bos/bb/gnu   |
|----------------------------|-----------|-----------|-----------|----------|----------|--------------------|
| 01-call-per-file           |        33 |      1678 |      2281 |   50.85x |   69.12x | 0/2000/2000        |
| 02-subst-per-file          |       307 |       849 |      1538 |    2.77x |    5.01x | 1000/1000/2000     |
| 03-text-pipeline           |      1088 |      1456 |       838 |    1.34x |    0.77x | 140/140/140        |
| 04-file-tree               |        48 |       917 |      1259 |   19.10x |   26.23x | 6/1061/1061        |
| 05-wc-tail                 |       378 |       994 |       505 |    2.63x |    1.34x | 0/400/400          |
| 06-sysinfo                 |       252 |       579 |      1017 |    2.30x |    4.04x | 200/540/540        |
| 07-shell-startup           |       131 |        84 |       139 |    0.64x |    1.06x | 100/100/100        |
| 08-subst-nofork            |        39 |       n/a |       n/a |        - |        - | 0/-/-              |

| footprint (shell + the commands above, on disk) | bytes |
|---|---|
| bashos: out/bash-static (statically linked) | 13638056 |
| busybox: /usr/bin/busybox (dynamically linked) | 826128 |
| gnu: bash + 28 separate binaries | 3948360 |

Repeated tool calls benefit most: the core profile created no child processes
for workload 01, compared with 2,000 for both external userlands. The long text
pipeline still took about 30% longer than GNU in both measurements. Static
linking reduced warm startup and idle RSS in these builds, while increasing
on-disk size; the profile determines how much optional functionality is carried.
