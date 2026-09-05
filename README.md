# bash-os

GNU bash, plus a curated set of **loadables compiled in as static builtins** —
so `ls`, `grep`, `sed`, `ps`, `httpd` and ~90 more are shell builtins, reached
with an empty `PATH`, no busybox and no coreutils. One binary is the shell and
the userland.

```
$ out/bash -c 'type -t ls; PATH=; printf "a\nb\n" | grep b'
builtin
b
```

## Why

Three uses drive it:

1. **A standalone bash binary** — one file that is a working shell *and* the
   commands a script needs, with nothing else installed. `./build.sh` produces it.
2. **Teaching bash as a real language** — the loadables are small, readable C
   that show how bash's builtin interface actually works.
3. **A userland for small Linux devices** — bash as PID 1 with these builtins
   replaces busybox on space- and fork-constrained boards. The
   `lichee-nano-bashos` appliance (a separate project) is the first such consumer.

## Build

```
./build.sh                 # host bash-os, 99 builtins injected -> out/bash
./build.sh --static        # a single statically-linked binary
./build.sh --list config/bash-loadables-pure.list   # a smaller variant
```

Cross-compiling for a device: set `CC` to your cross gcc and pass its `--host`
via `CONFIGURE_EXTRA=`; bash-os makes no host assumption. The bash source is
pinned by sha256 in `config/versions.sh`; a from-scratch build is byte-stable.

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

## Layout

```
build.sh                    the build
config/
  versions.sh               pinned bash source (sha256) + build number
  loadables.sh              the one parser of a loadables list
  bash-loadables.list       the injected set (NAME|short-doc per line)
loadables/                  the loadable C sources (the ones not in bash's tree)
  common/  _jsmn/           shared headers and a vendored JSON tokenizer
tests/
  host-smoke.sh             builds, then proves the builtins with an empty PATH
  run.sh                    the suite (smoke + the httpd/rngseed unit harnesses)
docs/PROVENANCE.md          where the code came from, and its licences
```

Names in `bash-loadables.list` that have no `loadables/NAME.c` here are bash's
own `examples/loadables/NAME.c`, taken from the pinned tarball at build time.

## Licence

MIT (`LICENSE`). The vendored JSON tokenizer (`loadables/_jsmn/`) is MIT
(zserge/jsmn, its own `LICENSE.txt`). See `docs/PROVENANCE.md`.
