# git

bash-os is growing a `git` builtin. It is not a wrapper: the formats are
implemented in C under `loadables/_git/`, and the builtin is the command
surface over them. This page tracks what it does today, and how that is
checked.

Nothing here is copied or translated from git, which is GPL-2.0. The
formats and the protocol come from their published descriptions.

## What exists today

Phase 0 of the port: repository discovery, the object store, refs and the
reflog, and the plumbing commands that exercise them.

```
git init         [-q] [--bare] [-b <branch>] [<directory>]
git rev-parse    [--git-dir] [--absolute-git-dir] [--show-toplevel]
                 [--is-inside-work-tree] [--is-bare-repository]
                 [--abbrev-ref] [--short[=N]] [--symbolic-full-name]
                 [--verify] [-q] <rev>...
git cat-file     (-t | -s | -e | -p | <type>) <object>
git hash-object  [-t <type>] [-w] [--stdin | --stdin-paths] [<file>...]
git update-ref   [-m <reason>] (-d <ref> [<old>] | <ref> <new> [<old>])
git symbolic-ref [-m <reason>] [-q] [--short] <name> [<ref>]
git show-ref     [--head] [--heads] [--tags] [-q] [--verify] [<pattern>...]
git for-each-ref [--count=<n>] [--format=<format>] [<pattern>...]
git reflog       [show] [<ref>]
```

Global options: `-C <path>`, `--git-dir=<path>`, `--work-tree=<path>`,
`--no-pager` (accepted, nothing paginates), `--version`, `--help` and
`--list-cmds`, which prints the commands this build has.

Reads cover loose objects, every pack, and the alternates named by
`objects/info/alternates` or `GIT_ALTERNATE_OBJECT_DIRECTORIES`. A
repository can be a worktree, a linked worktree (a `.git` file), or bare.
Ref changes are made under a `.lock` file and append a reflog entry, so
git reads what bash-os writes and the other way round.

A command or option this build does not have exits 129 and says so. It is
never silently ignored.

## Statuses and messages

git's: 0, 1, 128 for a fatal error, 129 for a usage error. Messages go to
stderr in git's wording, with no bash-os prefix, so a script written for
git sees what it expects.

## Each call runs in a child

`git` forks, and the command runs in the child. git reports a fatal
problem at any depth and stops; in a child that is simply an exit, so
nothing has to unwind the shell. `-C` can change directory without moving
the caller, the memory a history walk needs is returned at exit, and an
interrupt releases held lock files. The cost is one fork per call.

`obj`, `index` and `pack` stay in-process, for shell loops that call them
many times.

## How it is checked

`tests/git-parity.py` runs a scenario — a plain shell script of git
commands in `tests/git/` — twice in fresh directories: once with bash-os
(its own builtins, empty `PATH`) and once with real git. Both sides get
the same pinned environment, so object ids are reproducible.

It compares the run (exit status, stdout, stderr without `hint:` advice),
then the repository, read by real git in both trees: refs, HEAD, the
index, `status --porcelain=v2`, the stash, the whole history with its
identities and dates, the working tree's files with modes and digests, and
`fsck --strict`.

A scenario names the commands it needs in a `# requires:` line, and is
skipped while any of them is missing, so scenarios for later phases can
sit in the tree and start running as soon as their commands land.

`tests/git-odb.py` checks the object store directly against `git
cat-file`: loose objects, packed ones after `git gc`, abbreviations,
`--batch-check`, a linked worktree, a bare clone, alternates, `GIT_DIR`,
and that what `obj` writes git can read.

## Still to come

The porcelain itself: `add`, `commit`, `status`, `diff`, `log`, `branch`,
`switch`, `restore`, `reset` and `tag`, then merges and rebases, then
HTTPS and SSH remotes. The plan, including what each phase must match, is
in the implementation document for the port.
