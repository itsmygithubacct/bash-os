# Perl inside Bash

`bashperl` runs real Perl 5.44.0 in the Bash process. Its interpreter and standard
native extensions are linked into the executable as static archives. Running
`bashperl` does not start an external Perl process.

## Build

Select it explicitly, by itself or alongside a profile:

```sh
JOBS=4 ./build.sh --include bashperl --name perl
JOBS=4 ./build.sh --profile full --include bashperl --name full-perl
JOBS=4 ./build.sh --include bashperl --name perl --static
```

The first build downloads the SHA-256-pinned Perl source and builds a private
installation under `out/perl/TARGET`. This needs make, a native C compiler,
binutils, Python 3.12+, and network access for the first download. It does not
install system packages. Headers and libraries available on the build host
determine which optional native Perl extensions can be compiled.
The embedding build enables multiplicity and disables interpreter threads.

You can prepare or reuse the installation separately:

```sh
./build-perl.sh --jobs 4
./build.sh --include bashperl --name perl --perl-prefix out/perl/$(cc -dumpmachine)
```

`libperl` has no shared-library dependency at runtime. Perl's library files
(`.pm`, Unicode tables, and other module data) remain in the private prefix;
keep that installation when distributing a Perl-enabled binary. Plain Perl
programs that do not import modules can run with just the executable. `-I` and
`PERL5LIB` add module directories as usual; the default library paths use the
absolute prefix configured at build time. A fully static executable supports
the native extensions linked at build time; additional XS extensions need to
be included at link time. A dynamically linked Bash can also load compatible
XS shared objects.

Automatic Perl builds are native builds. Cross compilation requires an already
prepared, matching target installation supplied with `--perl-prefix`.

## Use

Inside a Perl-enabled Bash:

```sh
PATH=
bashperl -e 'print 6 * 7, "\n"'
bashperl -pe 's/error/ERROR/g' < application.log
bashperl -MJSON::PP -e 'print encode_json({answer => 42})'
bashperl script.pl "an argument"
```

Perl handles its own options: `-e`, `-E`, `-n`, `-p`, `-a`, `-F`, `-0`, `-l`,
`-i`, `-I`, `-M`, `-c`, and the rest of its CLI. With no script or `-e`, it reads
the program from standard input. Arguments reach `@ARGV` without another shell
parse. `bashperl -v` reports the embedded Perl version.

Each call has a fresh interpreter. Variables, loaded Perl packages and parser
state do not carry to the next call. `BEGIN` and `END` run with normal Perl
semantics. Syntax errors skip execution; the return status includes `exit`,
runtime errors, and changes made by `END` blocks.
Perl `fork` children exit after their Perl program finishes; they do not resume
the surrounding Bash script. `system` and `exec` retain their Perl behavior.

The shell's exported variables, including temporary assignments before the
command, initialize `%ENV`. Perl's changes to `%ENV` are private to that call.
The wrapper restores standard file descriptors and their flags, the current
directory, umask, locale, process name, signal handlers and signal mask. Default
Ctrl-C interrupts Perl and reaches Bash after this restoration; ignored SIGINT
stays ignored, and Perl programs may install their own signal handlers.

This is in-process native code. Explicit process operations such as `exec`,
`POSIX::_exit`, changing limits, or closing arbitrary nonstandard descriptors
affect the embedding process. Native XS extensions can also change process
state outside the wrapper's saved fields. Use `(bashperl ...)` when the program
needs process isolation. Perl's `$$` is the shell process ID and `$^X` identifies
the embedding executable; `$^X` is not a standalone Perl command-line launcher.

## Runtime loadable

The same sources can produce a module for `enable -f`. First prepare the Perl
prefix and a Bash build with headers, then run:

```sh
python3 config/build-perl-loadable.py
out/bash -c 'enable -f ./out/bashperl.so bashperl; bashperl -e '\''print "hello\n"'\'''
```

Use a Bash executable without an already embedded Perl. The module exposes the
Perl API for XS loading and keeps its code mapped after `enable -d` so native
loader callbacks remain valid. Disabling and re-enabling the builtin destroys
its interpreter resources; it does not unmap the library code.

## Checks

```sh
python3 tests/bashperl.py out/bash-perl
python3 tests/bashperl.py out/bash-perl-static
python3 tests/bashperl.py out/bash --module out/bashperl.so
python3 tests/profile-smoke.py out/bash-perl
python3 tests/perl-engine.py
bash tests/perl-check.sh
bash tests/bashperl-sanitize.sh out/bash-shell
```

The tests compare output and status with the pinned standalone Perl, then check
repeated invocations, native modules, shell state, interrupts, and module
unload/reload. The engine check verifies that signals stay blocked between
interpreter destruction and restoration of Bash's handlers. The executable
manifest records the Perl build and archive
checksums as well as the Bash binary checksum. Implementation sources are MIT;
Perl retains its own Artistic/GPL licensing and installed notices.
