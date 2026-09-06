# bash-os

GNU bash, plus a curated set of **loadables compiled in as static builtins** —
so `ls`, `grep`, `sed`, `ps`, `httpd`, `pax` and ~90 more are shell builtins,
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

```
./build.sh                                        # host, 100 builtins  -> out/bash
./build.sh --static                               # one self-contained file -> out/bash-static
./build.sh --list config/bash-loadables-pure.list # the 28-name POSIX baseline -> out/bash-pure
CC=riscv64-unknown-linux-musl-gcc ./build.sh      # cross -> out/riscv64-unknown-linux-musl/bash
```

Outputs are stripped (`--no-strip` keeps symbols) and each comes with a
`.manifest.txt` beside it. The bash source and the official bash-5.3 patch
set (001–010) are pinned by sha256 in `config/versions.sh`; a from-scratch
build is byte-identical to the last one.

Cross-compiling needs only `CC`: `--host` is derived from the compiler, and the
configure answers a cross build cannot measure itself (job control, named pipes,
`/dev/fd`, …) are supplied by `build.sh`. `CONFIGURE_EXTRA`, `CFLAGS` and
`LOCAL_LIBS` pass through; `LOCAL_LIBS` defaults to `-lm` for `fltexpr`.

Your own loadables, without forking the tree: `EXTRA_LOADABLES="dir …"` stages
more sources, and `--list` names the set to inject:

```
EXTRA_LOADABLES=docs/tutorial ./build.sh --list mine.list      # -> out/bash-mine
```

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
config/
  versions.sh                   pinned bash source (sha256) + build number
  loadables.sh                  the one parser of a loadables list
  bash-loadables.list           the full set (NAME|short-doc per line), 100 entries
  bash-loadables-pure.list      the 28 POSIX-utility loadables from bash's own tree
loadables/                      the loadable C sources this repo carries
  common/  _jsmn/               shared headers and a vendored JSON tokenizer
tests/
  run.sh                        the suite: everything below, for both list variants
  host-smoke.sh [BIN] [LIST]    every listed name is a builtin with help text,
                                and runs with an empty PATH (stat, pax, pipes …)
  stat-parity.sh [BIN]          stat against GNU coreutils' on the same files
  wc-tail-parity.sh [BIN]       wc and tail against GNU coreutils', both locales,
                                block edges, a stream not at its start
  rootfs-smoke.sh [STATIC-BIN]  a root filesystem of only the static binary runs
                                a script using a dozen commands (needs bwrap)
  tutorial.sh                   the tutorial's loadable, as a .so and compiled in
  regressions.py                builtin regressions in a real bash-os process
  licence-check.sh              every source states its licence (all MIT)
  httpd-host.c  rngseed-host.c  ASan+UBSan unit harnesses
docs/anatomy-of-a-loadable.md   how a builtin is put together, with docs/tutorial/greet.c
docs/PROVENANCE.md              where the code came from, and its licences
```

Names in a list that have no `loadables/NAME.c` here are bash's own
`examples/loadables/NAME.c`, taken from the pinned tarball at build time.

## Licence

Every source in this repository is MIT (`LICENSE`); the vendored JSON
tokenizer (`loadables/_jsmn/`) is MIT under its own `LICENSE.txt`.
`tests/licence-check.sh` holds the tree to that.

A built bash-os links GNU bash and is therefore distributed under the GPLv3,
whatever the loadables' own terms; MIT sources are GPL-compatible, and the MIT
grant is what lets each loadable be lifted into a non-GPL project on its own.
See `docs/PROVENANCE.md`.
