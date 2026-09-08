# Selecting the builtins in a binary

`./build.sh` defaults to the full collection. A profile selects which loadables
are compiled into the executable. GNU Bash's own builtins remain available in
every profile. Excluded loadables are absent from the binary; this is a build
choice, not a runtime disable list.

| Level | Profile | Injected commands | Native bytes | Intended use |
|---:|---|---:|---:|---|
| 0 | `shell` | 0 | 1,364,160 | GNU Bash alone |
| 1 | `pure` | 28 | 1,447,520 | Small baseline of POSIX utilities |
| 2 | `core` | 89 | 2,067,616 | Everyday files, text processing and processes |
| 3 | `device` | 160 | 2,734,528 | Core plus Linux devices, processes and basic networking |
| 4 | `server` | 214 | 6,943,104 | Device plus services, TLS, SSH, accounts and data |
| 4 | `desktop` | 155 | — | Core plus editors, terminal graphics and interactive tools |
| 5 | `full` | 279 | 11,169,864 | Every command in the collection |

Sizes are stripped x86-64 builds with GCC 14.2 and the default flags. See the
[benchmarks](../bench/README.md) for static sizes, startup and resident memory.
Desktop size awaits measurement after adding the native PTY broker.
Those profiles include `ptybroker`; desktop also includes `bashpoll` for
descriptor readiness. `screen` requires its `ptybroker` companion in custom lists.

Levels 0–5 select `shell`, `pure`, `core`, `device`, `server`, and `full`.
`desktop` is an alternative to `server`; select it by name. The definitions in
[`config/profiles.json`](../config/profiles.json) are authoritative. Profiles
choose useful command groups; they do not imply that every command implements
the full corresponding GNU utility.
The [loadable status table](loadables-status.md) records profile membership,
tested behavior, known limitations and individual comparison timings. Use its
[CSV](loadables-status.csv) to filter candidates before choosing an inclusion list.

```sh
./build.sh --list-profiles
./build.sh --profile core                 # out/bash-core
./build.sh --level 3 --static             # out/bash-device-static
./build.sh --profile desktop              # out/bash-desktop
./build.sh --profile full --static        # out/bash-static
```

## Exact inclusion lists

A list contains one `NAME` or `NAME|SHORT-DOC` per line. Blank lines and lines
beginning with `#` are ignored. Leading/trailing whitespace is trimmed. Names
must be unique. Help text can contain quotes, backslashes and additional `|`
characters. Inspect available names with `--list-loadables`.

```sh
printf 'cut\nseq\n' > selected.list
./build.sh --list selected.list           # exactly cut and seq; out/bash-selected
./build.sh --include cut,seq --name small # same commands; out/bash-small
```

`--list` selects an exact base instead of a profile. With `--include` or
`--include-list` alone, the base is empty. Repeated additions are deduplicated
and preserve their first position; a later help entry overrides earlier help.

```sh
./build.sh --profile core --include nano,ts --name editor
./build.sh --profile device --include-list selected.list --name appliance
./build.sh --profile full --exclude termpixel_pong --name custom
./build.sh --include-list selected.list --include wc --name counting
```

Exclusions apply after additions. Companion builtins must be selected explicitly:
for example, `nano` needs `ts`, `zstdcat` needs `zstd`, `pkill` needs `pgrep`, and
`doas` and `sudo` need each other. An incomplete or unknown selection fails
before downloading or compiling. Shared C helpers and link libraries are
selected automatically from [`config/helpers.json`](../config/helpers.json).

## Inspecting and reproducing a selection

These commands resolve the selection without invoking a compiler:

```sh
./build.sh --profile server --show-config
./build.sh --profile core --include nano,ts --print-list > editor.list
./build.sh --list editor.list
```

Customized selections get `out/bash-custom-HASH` unless `--name TAG` is set.
An unmodified full build uses `out/bash`; other profiles use `out/bash-PROFILE`.
`--static` appends `-static`, and cross builds add an `out/TARGET/` directory.
Each binary has three companion files:

- `.loadables.list`: its resolved, reusable inclusion list.
- `.manifest.json`: command names, helpers, libraries, target, link mode, size
  and binary SHA-256.
- `.manifest.txt`: a short human-readable build record.

`python3 tests/profile-smoke.py out/bash-core` checks the binary checksum and
proves that its injected builtin set matches the manifest, with `PATH` empty.
The build cache includes the selection, sources, helper metadata, compiler,
flags and any explicit dependency prefix. Builds in one checkout serialize
through a lock; use separate worktrees for concurrent builds.

`EXTRA_LOADABLES="dir …"` adds your own C sources to the catalog. Use their names
in an inclusion list or `--include`. See the [loadable tutorial](anatomy-of-a-loadable.md).

## Dependency libraries and cross builds

All builds need a C compiler, make, Python 3.9+, curl, patch, GNU binutils and
`flock`. The `shell`, `pure`, `core`, and `device` profiles need no extra codec,
regex, database or TLS development libraries. Other selections may use PCRE2,
zlib, liblzma, libzstd and bzip2. The build resolves only the libraries needed by
the selected commands. Static builds require static archives.

`build-deps.sh` builds pinned static archives for all five external libraries.
It additionally needs CMake and Python 3.12+. URLs and SHA-256 checksums are in
[`config/dependencies.json`](../config/dependencies.json). It installs headers,
archives, license notices and a build record into a private prefix, and refuses
to replace a nonempty prefix it did not create.

```sh
# Host libraries, independent of distribution development packages:
./build-deps.sh
./build.sh --static --deps-prefix "out/deps/$(cc -dumpmachine)"

# Target libraries, without changing the compiler's sysroot:
export CC=riscv64-unknown-linux-musl-gcc
JOBS=4 ./build-deps.sh
JOBS=4 ./build.sh --profile full --static \
  --deps-prefix out/deps/riscv64-unknown-linux-musl
bash tests/cross-smoke.sh out/riscv64-unknown-linux-musl/bash-static
```

`CC` must name a single compiler executable. Matching archive tools are derived
from a `*-gcc` name; `AR` and `RANLIB` can override them. Use `--prefix DIR` for a
different dependency installation location. `CFLAGS` controls dependency builds;
`CFLAGS`, `CPPFLAGS`, `LDFLAGS_EXTRA`, `LOCAL_LIBS` and `CONFIGURE_EXTRA` also pass
through to the Bash build. `--host` and Linux configure answers are derived for
cross compilation.

The cross test needs `qemu-riscv64`, registered RISC-V binfmt support for guest
self-execution, Python `cryptography`, and host fixture utilities. For a dynamic
executable, export `QEMU_LD_PREFIX` pointing at its target sysroot. CPU-specific
SDK code may also need `QEMU_CPU`; both variables must be exported so nested
guest execution receives the same settings. QEMU verifies userspace behavior;
it does not validate board devices or drivers.

## Automated checks

The [CI workflow](../.github/workflows/test.yml) builds every named profile and
a custom list, runs native dynamic/static behavior and sanitizer tests, builds
the pinned dependencies for a full static RISC-V executable and runs it under
QEMU. It also runs bounded LDAP BER/filter, image-decoder and TOML fuzzing with
Clang's libFuzzer, AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
./build.sh --profile shell
FUZZ_SECONDS=60 bash tests/fuzz.sh
```

Fuzz inputs and logs remain in ignored `out/fuzz/`. Each parser gets the time
budget independently. These runs supplement deterministic regression fixtures;
they are not an exhaustive claim about malformed inputs.
