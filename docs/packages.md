# Loadable packages

A dynamic bash-os build can load a command it was built without. `pkg`
installs the command from a signed package, and `pkg load` (or `enable -f`)
makes it a builtin in the running shell.

## What a package holds

A package is an uncompressed ustar archive named `NAME_VERSION_ARCH.pkg` with
two members:

- `MANIFEST`: `name`, `type: loadable`, `version`, `builtin`, `abi: bash-5.3`,
  `arch`, the SHA-256 of the object, a description, and the mode pkg installs
  the object with;
- `loadable/NAME.so`: the builtin as a shared object.

The object needs no shared library but glibc's own: `libc.so.6`, `libm.so.6`
and the dynamic loader, which are present beside every dynamic bash. Linking
against them records the symbol version of each reference; an unversioned
reference binds glibc's oldest compatibility version, such as a `regexec` that
ignores `REG_STARTEND`. Everything else the builtin uses is linked into the
object: helper sources, builtins it calls, and static libraries from
`build-deps.sh`. The object binds its own symbols first, so loading it into a
shell that already has a builtin of that name replaces that builtin without
mixing code from the two.

A package may also carry files of its own under `libexec/NAME/` and
`share/NAME/`, such as a program the builtin runs or a library it reads.
pkg installs them under `/usr/lib/bash-os/libexec/NAME` and
`/usr/lib/bash-os/share/NAME`. MANIFEST declares each file with its permission
bits and SHA-256:

```
data: share/NAME/lib/os.py 0644 SHA256
```

Every file in those trees must be declared, and every declared file present
with the same mode and content; links, setuid bits and paths outside the two
trees are refused. Install writes each tree beside the old one and swaps it
in, so an upgrade leaves no stale files and a failed install leaves the old
tree in place. `pkg remove` deletes the trees with the loadable, and
`pkg verify NAME` reports missing, extra and changed files.

Packages load only into dynamic executables built for the same architecture,
with glibc, from the same Bash release. A static executable cannot load shared
objects at all.

## Building packages

```sh
./build.sh --profile shell       # the smallest dynamic bash: out/bash-shell
./build-deps.sh                  # static PIC zlib, PCRE2, xz, zstd and bzip2
./build-packages.sh              # every command -> out/packages/x86_64/
./build-packages.sh seq wc awk   # or only these
```

`build-packages.sh` stages sources as `build.sh` does: this repository's
loadables, Bash's example loadables with the fixups `build.sh` applies, and
the flattened helpers. It compiles them against the Bash tree the last build
left behind (`--tree`), which must come from a dynamic build for the same
target. If `./build.sh --profile shell` reports that it is up to date after a
different build has replaced the tree, add `--clean`.

An object is packed only after two gates:

1. every strong undefined symbol is defined by `out/bash-shell` (`--bash`), by
   a library it needs, or by its program interpreter, and every reference to
   glibc carries a symbol version. Checking against the smallest build means a
   package that passes loads into every dynamic profile;
2. that bash loads the object with `enable -f`, and `type -t` reports a
   builtin.

A source that defines no `NAME_struct` (`wc.c`, for one, registers
`bashwc_struct`) gets the entry that `build.sh`'s builtin table gives it: its
`NAME_builtin`, its `NAME_doc`, and the short help from
`config/bash-loadables.list`.

The output directory receives the packages, an unsigned `INDEX` with one
`pkg-loadable-v1` record per package, and `build-report.tsv` with each
command's object size or failure reason. The exit status is 1 if any command
failed. The version defaults to the date of the HEAD commit; `--version`
overrides it. With the same sources, compiler and version, the packages and
the INDEX are identical byte for byte.

`--data NAME=DIR` adds `DIR/libexec/NAME/` and `DIR/share/NAME/` to NAME's
package, which is then xz-compressed. Names may also come from
`config/bash-loadables-optional.list`, which the default catalog leaves out.

For another architecture, set `CC` as for `build.sh`, and pass `--runner` with
a command that runs the target's executables, such as qemu-user with the
target's library directory.

## uv

The optional `uv` package holds a small builtin and upstream's static uv
executable, pinned by version and SHA-256 in `config/uv.json`:

```sh
python3 config/fetch-uv.py x86_64 --out out/uv/x86_64    # checks the pinned SHA-256
./build-packages.sh --data uv=out/uv/x86_64 uv
```

After `pkg install uv` and `pkg load uv`, the builtin runs
`/usr/lib/bash-os/libexec/uv/uv` as the shell runs an external command: with
the exported variables, default SIGINT and SIGQUIT, and uv's exit status. It
works with an empty `PATH`. uv runs as its own process because its entry
point assumes a fresh process that has started no threads. It exits 127, and
says to install it, when the program is missing. uv is licensed MIT or
Apache-2.0.

## Signing a release

```sh
./sign-packages.sh keygen ~/keys bash-os-2026    # once: .pub and .sec
./sign-packages.sh release --key ~/keys/bash-os-2026.sec \
  --out out/release out/packages/x86_64 out/packages/aarch64
```

Keys are in signify format. The secret key has no passphrase and is written
with mode 0600, so keep it on the machine that signs, never in a repository or
a CI secret. `release` checks every package against the SHA-256 in its INDEX,
then fills a new directory with:

- each package and its signature, `NAME_VERSION_ARCH.pkg.sig`;
- one `INDEX` covering every architecture, and `INDEX.sig`;
- `SHA256SUMS`.

A GitHub release holds at most 1000 assets, and every package for three
architectures, with signatures, needs about 1700. So bash-os publishes each
architecture's packages as a release of its own, and a rolling release named
`packages` holds only the signed INDEX:

```sh
./sign-packages.sh release --key ~/keys/bash-os-2026.sec --out out/release \
  --asset-url 'https://github.com/itsmygithubacct/bash-os/releases/download/packages-{version}-{arch}' \
  out/packages/x86_64 out/packages/aarch64 out/packages/riscv64
```

With `--asset-url`, each INDEX record names its package and signature by
absolute URL, and they go in one directory per architecture. Upload
`out/release/ARCH` as release `packages-VERSION-ARCH`, then replace `INDEX`,
`INDEX.sig` and `SHA256SUMS` in release `packages`. pkg refuses an INDEX
until its matching `INDEX.sig` is in place, so a half-finished upload is never
trusted. Without `--asset-url`, nothing is nested, and the directory can be
served as a repository as it is.

## Installing

pkg trusts the bash-os publisher key, and its successor for rotation, with no
configuration: both are compiled in. It also trusts any `.pub` file in
`/etc/bashsignify/trusted` (or `$BASHSIGNIFY_TRUSTED_KEYS_DIR`). Key numbers
listed in `/etc/bashsignify/revoked-keys` are refused, the built-in keys
included.

With no `/etc/pkg/sources.list`, pkg uses the bash-os releases,
`https://github.com/itsmygithubacct/bash-os/releases/download/packages`:

```sh
pkg update --remote    # fetch the INDEX and check INDEX.sig
pkg install awk        # fetch the package and check its signature and object
pkg load awk           # enable it in this shell
```

To use other repositories, list their URLs in `/etc/pkg/sources.list`, one per
line. `https://` sources need `--remote`, and `http://` sources need
`--remote-insecure`; a line may instead begin with `remote` or
`remote-insecure`. Downloads follow redirects, as release hosting sends them
to a storage host, and every INDEX and package is still checked against its
signature.

## Tests

`tests/packages.py` builds ten packages twice and compares the bytes, checks
that the producer and the signer refuse bad input, serves a signed release
over HTTP, and installs every package with an empty `PATH`. It then runs each
builtin in `out/bash-shell` and compares the output with the same builtin
compiled into `out/bash`. `tests/pkg-signify.py` covers pkg's signature,
trust, revocation and dependency checks. `tests/pkg-data.py` installs,
verifies, upgrades and removes a package with data trees, and checks that
archives whose data disagrees with MANIFEST are refused. `tests/run.sh` runs
all three.
