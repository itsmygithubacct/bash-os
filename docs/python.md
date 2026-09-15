# Python inside Bash

`bashpython` runs real CPython 3.13 from Bash. The interpreter, its standard
native extension modules, and the libraries they use are linked into the
executable or into `bashpython.so` as static archives. Each call runs in a
child of the shell, so no external Python program is started and no
interpreter state reaches the shell.

## Build

Select it explicitly, by itself or alongside a profile:

```sh
JOBS=4 ./build.sh --include bashpython --name python
```

The first build downloads the SHA-256-pinned CPython source and builds a
private installation under `out/python/TARGET`. It needs make, a native C
compiler, binutils, Python 3 and network access for the first download, plus
the static zlib, bzip2 and xz from `./build-deps.sh`. SQLite comes from the
copy vendored in `loadables/_sqlite`. It does not install system packages.

You can prepare or reuse the installation separately:

```sh
./build-python.sh --jobs 4
./build.sh --include bashpython --name python --python-prefix out/python/$(cc -dumpmachine)
```

The installation is built with `--disable-shared`, `-fPIC` and
`MODULE_BUILDTYPE=static`, so every standard extension module is part of
`libpython`. Optional modules follow what the build host provides as static
libraries:

| Module | Needs | Without it |
|---|---|---|
| `_ctypes` | `libffi.a` | `ctypes` is unavailable |
| `_ssl`, `_hashlib` | `libssl.a`, `libcrypto.a` | no `ssl`; `hashlib` keeps its built-in algorithms |
| `_uuid` | `libuuid.a` | `uuid` uses its pure Python fallback |

Never built: `readline` and `_curses`, which would duplicate the readline and
terminfo code Bash already exports; `_tkinter`, `_gdbm` and `_dbm`. The
interactive prompt works without `readline`, with plain line editing.

The standard library is precompiled once, without the optimization-level
variants, and trimmed of test packages, IDLE, tkinter, turtledemo and
ensurepip. `out/python/TARGET/data/share/bashpython` holds it in the layout
pkg installs.

`./build.sh` builds the installation automatically only for a native compiler.
For another architecture, build the native installation first, then OpenSSL
and libffi for the target with `build-deps.sh --python`, and the target
installation with the native interpreter as its build Python:

```sh
CC=aarch64-linux-gnu-gcc ./build-deps.sh --python
CC=aarch64-linux-gnu-gcc ./build-python.sh \
  --build-python out/python/x86_64-linux-gnu/bin/python3.13 \
  --runner 'qemu-aarch64 -L /usr/aarch64-linux-gnu'
```

The runner lets the build run the target interpreter to check which modules
it compiled in. `build-deps.sh --python` also serves native builds, which then
use its OpenSSL and libffi instead of the build host's.

## Use

```sh
PATH=
bashpython -c 'print(6 * 7)'
bashpython -m json.tool < data.json
bashpython script.py "an argument"
printf 'print("hi")\n' | bashpython -
bashpython                 # interactive prompt on a terminal
```

Python handles its own options: `-c`, `-m`, `-I`, `-E`, `-S`, `-u`, `-X`, `-V`,
a script, `-` for standard input, and the rest of its command line. Arguments
reach `sys.argv` without another shell parse.

The shell's exported variables, including temporary assignments before the
command, form Python's `os.environ`; unexported shell variables do not.
Python's changes to its environment, current directory, umask, signal handlers
and descriptors stay in the child. The exit status is Python's. An unhandled
`KeyboardInterrupt` ends the child with SIGINT and then interrupts the shell,
as it would after a standalone `python3`; a program that catches it returns its
own status.

`bashpython` does not provide a `python3` executable:

- `sys.executable` does not name a Python launcher, so code that runs
  `sys.executable` in a subprocess does not start Python;
- `multiprocessing` with the `spawn` or `forkserver` start method does not work;
  the default `fork` method does;
- `venv` cannot create environments, and ensurepip is not included.

Pure Python packages work through `PYTHONPATH`. Separately built C extensions
need the same CPython version and ABI; the module exposes the full C API for
them.

`ssl` uses the OpenSSL linked in at build time, whose default certificate
locations are the build host's (`/usr/lib/ssl` on Debian). Where those do not
exist, set `SSL_CERT_FILE`, for example to `/etc/ssl/cert.pem`, or pass a
context with explicit certificates.

## Runtime loadable

The same sources produce a module for `enable -f`. Prepare the Python prefix
and a Bash build with headers, then run:

```sh
python3 config/build-python-loadable.py
```

`out/bashpython.so` needs no shared library but glibc's `libc.so.6`,
`libm.so.6` and dynamic loader, the dependencies pkg accepts, and passes the
same symbol and load checks as `build-packages.sh`. It is linked against glibc
normally, so its references carry symbol versions: an unversioned reference
binds a symbol's oldest version, and glibc's oldest condition variables cannot
start Python. The build refuses a module that does not run a threaded Python
program in `out/bash-shell`. Installed by pkg as
`/usr/lib/bash-os/loadables/bashpython.so`, it finds its standard library in
`/usr/lib/bash-os/share/bashpython`, relative to its own location. `PYTHONHOME`
overrides that.

## Package

pkg installs the module and its standard library together:

```sh
pkg install bashpython
pkg load bashpython
bashpython -c 'import sys; print(sys.version)'
```

`/usr/lib/bash-os/share/bashpython` holds the standard library, and
`pkg verify bashpython` rechecks every one of its files. [Loadable
packages](packages.md) describes how the package is built.

## Checks

```sh
python3 tests/bashpython.py out/bash-python
python3 tests/bashpython.py out/bash-shell --module out/bashpython.so
python3 tests/bashpython-package.py out/bash-pkg
bash tests/python-check.sh      # all of the above, as CI runs it
```

The tests compare output and status with the standalone build of the same
CPython for `-c`, `-m`, script files, standard input, exit codes, exceptions
and the compiled-in modules. They also check the environment, current
directory and umask the shell keeps, repeated calls, and interrupts both
unhandled and caught. Implementation sources are MIT; CPython retains the PSF
license, installed with its notices.
