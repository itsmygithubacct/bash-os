# Anatomy of a loadable

bash has had loadable builtins since 2.0: a shared object that defines a
function and a table entry, which `enable -f` adds to the running shell.
bash-os takes the same file and compiles it *into* bash, so the command is
there before the first prompt with nothing on disk to load. This page walks
through one loadable, `docs/tutorial/greet.c`, and the three ways to run it.

```
$ greet -n 2 -u bash
hello, BASH
hello, BASH
$ help greet | head -1
greet: greet [-n TIMES] [-u] [NAME]
```

## The four parts of a builtin

Open `docs/tutorial/greet.c` alongside this. Every loadable in `loadables/`
has the same four parts, whatever else it does.

**1. The entry point** — `int greet_builtin (WORD_LIST *list)`. bash calls it
with the command's arguments as a linked list of words; `list->word->word` is
the first argument's text, `list->next` the rest. It runs *inside the shell
process*: no fork, no exec, `$?` is whatever it returns.

**2. Option parsing** — bash's own `internal_getopt (list, "n:u")` walks the
list like `getopt(3)`: a letter followed by `:` takes an argument, delivered
in `list_optarg`. After the loop, `loptend` is the list with the options
removed, so `list = loptend` leaves only the operands. `CASE_HELPOPT` makes
`--help` print the long documentation; `builtin_usage ()` prints the one-line
usage on a bad option, and `EX_USAGE` (2) is the conventional status for it.

**3. The work** — plain C. Output goes to the shell's `stdout`; flush it
before returning so it stays ordered with the script's own `echo`. Report
problems with `builtin_error ("...")`, which prefixes the builtin's name the
way bash does for its own commands.

**4. The status and the table entry** — the return value becomes `$?`;
`EXECUTION_SUCCESS` is 0 and `EXECUTION_FAILURE` is 1. `sh_chkwrite (status)`
turns a failed write on stdout (a closed pipe) into a failure. Then two
definitions bash looks for by name:

```c
char *greet_doc[] = { "Print a greeting.", "", "...", (char *)NULL };   /* help greet */
struct builtin greet_struct = {
  "greet", greet_builtin, BUILTIN_ENABLED, greet_doc, "greet [-n TIMES] [-u] [NAME]", 0
};
```

The `NAME_builtin` / `NAME_doc` / `NAME_struct` naming is the contract:
`enable -f` looks the struct up by name, and `build.sh` splices a row built
from `NAME_builtin` and `NAME_doc` into bash's own table.

## Running it three ways

### As a shared object, for iteration

Build bash-os once (`./build.sh`) so `build/bash-5.3/` holds the configured
headers, then compile against them and load the result into a running shell:

```sh
BT=build/bash-5.3
cc -fPIC -shared -DHAVE_CONFIG_H -I$BT -I$BT/include -I$BT/builtins -I$BT/examples/loadables \
   docs/tutorial/greet.c -o greet.so
out/bash -c 'enable -f ./greet.so greet; greet -u you; type -t greet'
```

`type -t` says `builtin`. Edit, recompile, `enable -d greet; enable -f` again:
the loop is seconds.

### Compiled in

Put the file where the build finds it and name it in a list:

```sh
cp docs/tutorial/greet.c loadables/
printf 'greet|Print a greeting\n' >> config/bash-loadables.list
./build.sh
out/bash -c 'greet; type -t greet'
```

Or, without touching the tree, point the build at a directory of your own
loadables and your own list:

```sh
printf 'greet|Print a greeting\n' > /tmp/mine.list
EXTRA_LOADABLES=docs/tutorial ./build.sh --list /tmp/mine.list    # -> out/bash-mine
```

That binary has exactly one extra builtin, and `PATH=` cannot take it away.
This is what `tests/tutorial.sh` does.

### As part of a userland

`./build.sh --static` makes one file that is the shell and every builtin in
the list. `tests/rootfs-smoke.sh` drops it into an otherwise empty root
filesystem and runs a script that uses a dozen commands; a loadable you add
to the list is there too. That is how bash-os replaces busybox on a small
device: no `/bin` full of applets, one binary, forks only when *you* fork.

## Things a builtin must remember

A loadable is not a program. The process it runs in is the user's shell, and
on a bash-os device it may be PID 1 for months.

- **Free what you allocate and close what you open.** A leak per call is a
  leak per loop iteration. The `gcc -fanalyzer` pass in review looks for
  exactly this.
- **Never call `exit()`.** That is the shell exiting. Return a status.
- **Do not keep state in globals across calls** unless it is meant to be a
  daemon's state (`bashsyslogd`, `httpd` do this deliberately).
- **Reset your getopt.** `reset_internal_getopt ()` before the loop, every
  call.
- **Check for bash's own names.** A loadable named `false` collides with the
  builtin bash already has; the table is one namespace.

## Reading further

`loadables/stat.c` is a complete, realistic builtin in 400 lines: the
coreutils `stat` surface with option parsing, formatted output, an error path
per file, and an associative-array result via `bind_assoc_variable`.
`loadables/cat.c` in bash's own tree (fetched to `build/bash-5.3/examples/loadables/`)
is the smallest useful one. bash's `builtins/*.def` are the same shape with a
preprocessor around them — read `builtins/echo.def` and you will recognise
every part above.
