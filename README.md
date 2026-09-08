# bash-os

GNU bash, plus a curated set of **loadables compiled in as static builtins** —
so `ls`, `grep`, `sed`, `ps`, `httpd`, `pax`, `flock`, `expr` and 271 more are builtins,
reached with an empty `PATH`, no busybox and no coreutils. One binary is the
shell and the userland.

```
$ out/bash -c 'type -t ls; PATH=; printf "a\nb\n" | grep b'
builtin
b
```

## Why

Three uses drive it:

1. **A standalone bash binary** — one file that is a working shell *and* the
   commands a script needs, with nothing else installed. `./build.sh --static`
   produces it.
2. **Teaching bash as a real language** — the loadables are small, readable C
   that show how bash's builtin interface actually works.
   `docs/anatomy-of-a-loadable.md` walks through one, `docs/tutorial/greet.c`,
   and the three ways to run it; `tests/tutorial.sh` keeps the page honest.
3. **A userland for small Linux devices** — bash as PID 1 with these builtins
   replaces busybox on space- and fork-constrained boards. The
   `lichee-nano-bashos` appliance (a separate project) is the first such consumer.

## Build

```sh
./build.sh                                     # full collection -> out/bash
./build.sh --profile core                       # everyday tools -> out/bash-core
./build.sh --level 3 --static                    # device tools -> out/bash-device-static
./build.sh --profile desktop                     # editors and terminal graphics
./build.sh --include cut,seq --name small        # exactly two injected builtins
./build.sh --list selected.list                  # your exact inclusion list
./build.sh --profile core --include nano,ts       # profile plus selected commands
./build.sh --list-profiles                       # levels, sizes of command sets, purposes
```

Choose `shell`, `pure`, `core`, `device`, `server`, `desktop`, or `full`.
Levels 0–5 range from no injected loadables to the full collection. Lists and
repeatable `--include`, `--include-list`, and `--exclude` options let you choose
exactly what goes into a binary. Required companion builtins are checked before
compilation; shared C helpers and libraries are selected automatically.

Outputs are stripped (`--no-strip` keeps symbols). Each binary comes with a
resolved `.loadables.list`, a `.manifest.json` with its selection and checksum,
and a readable `.manifest.txt`. The Bash 5.3 source and official patches 001–015
are pinned by SHA-256 in `config/versions.sh`.

All builds need Python 3 and the usual C build tools. The first four profiles
need no additional development libraries. Larger selections may need PCRE2,
zlib, liblzma, libzstd and bzip2. `build-deps.sh` builds pinned static libraries
for a host or cross compiler in a private prefix:

```sh
CC=riscv64-unknown-linux-musl-gcc ./build-deps.sh
CC=riscv64-unknown-linux-musl-gcc ./build.sh --static \
  --deps-prefix out/deps/riscv64-unknown-linux-musl
```

See [build profiles](docs/build-profiles.md) for the profile table, list format,
output naming, dependencies, cross testing and your own `EXTRA_LOADABLES`.
The [loadable status table](docs/loadables-status.md) and
[CSV](docs/loadables-status.csv) list every loadable, its profiles, test evidence,
BusyBox/Linux comparison data and recommended next work.
The [head/sed](docs/head-sed.md), [fold](docs/fold.md),
[expand](docs/expand.md), [bc](docs/bc.md), [nl](docs/nl.md),
[pr](docs/pr.md) and [tac](docs/tac.md) reports describe the corrected behavior,
measured workloads and remaining option limits.

`gpu`, included in `desktop` and `full`, adds a persistent pixel canvas, terminal
input, image export and optional GLES2 shader rendering. Run
`out/bash-desktop examples/gpu-dashboard.sh` for a live system graph, or
`out/bash-desktop examples/gpu-shader.sh` for an animated shader.
[Graphics from Bash](docs/gpu.md) covers drawing, transport fallback and the
Kilix DMA-BUF path. The canvas works without graphics drivers; shader rendering
loads GBM/EGL/GLES libraries on demand.

`ptybroker` provides independent local PTYs with bounded binary I/O and
attach/detach. `screen` uses it for live panes, targeted input and resizing.
[Persistent local PTYs](docs/ptybroker.md) documents the commands and their
raw-history contract. Both commands are included in `desktop` and `full`.

## How much it saves

`bench/run.sh` runs the same POSIX scripts under three userlands — bash-os
with an empty `PATH`, busybox with its applets, and bash with the GNU tools —
and reports wall time and processes created. See `bench/README.md` for the
method and the numbers; the short version is that a script which calls a
tool per file runs an order of magnitude faster, and one long pipeline does
not.

## How it works

bash 5.3 lets a loadable be enabled at runtime with `enable -f`. bash-os instead
bakes them in at build time (`build.sh`):

1. each listed loadable is copied into bash's `builtins/`, its relative includes
   rewritten and its `NAME_builtin`/`NAME_doc` un-`static`-ed;
2. `NAME.o` is added to `OFILES` so it lands in `libbuiltins.a`;
3. after `mkbuiltins` generates the builtin table, `extern` decls and
   `shell_builtins[]` rows are spliced in. bash 5.3 sizes `num_shell_builtins`
   with `sizeof()`, so the count needs no editing.

The result is indistinguishable from a native builtin: `type ls` says
"ls is a shell builtin", and `enable -n ls` disables it.

`env`, `nice`, `nohup`, `xargs`, and `find -exec` run enabled builtins in a
child process, preserving literal arguments and isolating command state from
the caller. Explicit executable paths and disabled builtin names use external
command lookup.

## Layout

```
build.sh                        the build
build-deps.sh                   pinned host/target dependency libraries
config/
  versions.sh                   pinned bash source (sha256) + build number
  loadables.py                  list parser and profile resolver
  loadables.sh                  shell interface to the parser
  profiles.json                 named inclusion profiles
  dependencies.json             pinned external libraries
  bash-loadables.list           the full set (NAME|short-doc per line), 279 entries
  bash-loadables-pure.list      the curated 28-command baseline
loadables/                      the loadable C sources this repo carries
  common/  _jsmn/               shared headers and a vendored JSON tokenizer
tests/
  run.sh                        full, pure, static, runtime and sanitizer checks
  profiles.py                   selection and dependency contracts
  profile-smoke.py BIN          exact injected set and manifest checksum
  cross-smoke.sh BIN            full RISC-V fixtures under QEMU
  input-lifetime.py [BIN]       mixed readers and descriptor ownership across libcs
  fuzz.sh                       bounded LDAP, image and TOML parser fuzzing
  host-smoke.sh [BIN] [LIST]    every listed name is a builtin with help text,
                                and runs with an empty PATH (stat, pax, pipes …)
  stat-parity.sh [BIN]          stat against GNU coreutils' on the same files
  cut-parity.sh [BIN]           cut against GNU coreutils' on the same inputs: every
                                option, the range-list errors, the 64 KB block edge
  wc-tail-parity.sh [BIN]       wc and tail against GNU coreutils', both locales,
                                block edges, a stream not at its start
  grep-parity.sh [BIN]          grep against GNU grep's: both dialects, every
                                flag, -w/-x, context, binary files, block edges
  sort-parity.sh [BIN]          sort against GNU coreutils, numeric and field keys
  seq-parity.sh [BIN]           seq against GNU coreutils' with the same argv words:
                                integers, floats, -w -s -f, big counts, the error cases
  rootfs-smoke.sh [STATIC-BIN]  a root filesystem of only the static binary runs
                                a script using a dozen commands (needs bwrap)
  tutorial.sh                   the tutorial's loadable, as a .so and compiled in
  regressions.py                builtin regressions in a real bash-os process
  licence-check.sh              source licences and third-party notices
  zstd-check.sh [BIN]           zstd against the host's zstd(1): round trips, interop, semantics
  util-linux-smoke.sh [BIN]     the util-linux family: help, safe operations, host parity
  system-smoke.sh [BIN]        process/system queries and temporary-file operations
  network-smoke.py [BIN]       framing, loopback transfers, subprocess failures
  terminal-smoke.py [BIN]      key decoding, pseudo-terminals, editing and replay
  terminal-sanitize.sh [BIN]   the terminal checks with instrumented modules
  misc-smoke.py [BIN]          arithmetic, scheduling, file formats and helpers
  large-smoke.py [BIN]         calculators, JSON, services, disks and tool subsets
  helper-smoke.py [BIN]        compression, SQLite, TOML, Unicode and terminal helpers
  procstat-smoke.py [BIN]      process-accounting fixtures
  final-smoke.py [BIN]         crypto, TLS, accounts, Git, protocols, images and editors
  final-sanitize.sh [BIN]      final imports and their helpers under ASan/UBSan
  gpu-smoke.py [BIN]           canvas pixels, transport fallback, input and cleanup
  gpu-sanitize.sh [BIN]        graphics and raster code under ASan/UBSan
  gpu-live.py [BIN]            optional isolated Kilix integration check
  {head-sed,fold,expand,bc,nl,pr,tac}-parity.py [BIN]
                                command parity and persistent-shell input/output
  {head-sed,fold,expand,bc,nl,pr,tac}-sanitize.sh [BIN]
                                the same focused checks under ASan+UBSan
  paste-uniq-parity.py [BIN]    record/group parity, output errors and shell state
  text-tools-parity.sh [BIN]    expand, tac, join, pr, expr, hexdump, column … vs the host's
  httpd-host.c  rngseed-host.c  zstd-host.c   ASan+UBSan unit harnesses
  grep-host.c                   grep as a program: the parity cases under ASan+UBSan
docs/anatomy-of-a-loadable.md   how a builtin is put together, with docs/tutorial/greet.c
docs/loadables-status.md       complete inventory, correctness findings and benchmarks
docs/loadables-status.csv      filterable loadable status and work priorities
docs/PROVENANCE.md              where the code came from, and its licences
```

Names in a list that have no `loadables/NAME.c` here are bash's own
`examples/loadables/NAME.c`, taken from the pinned tarball at build time.

## Licence

The project sources are MIT (`LICENSE`). Vendored helpers retain their own
licences, including MIT, ISC, BSD, Apache-2.0, LGPL-2.1, Unicode terms,
and public-domain dedications. The inventory in
`config/helpers.json` names each helper’s licence and notice file; see
[provenance](docs/PROVENANCE.md) for versions and adaptations.
`tests/licence-check.sh` holds the tree to that.

A built bash-os links GNU bash and is therefore distributed under the GPLv3,
whatever the loadables' own terms. Reusing an MIT wrapper also requires
following the terms of any helper libraries that it uses.
See `docs/PROVENANCE.md`.
