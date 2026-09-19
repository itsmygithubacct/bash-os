# git

bash-os is growing a `git` builtin. It is not a wrapper: the formats are
implemented in C under `loadables/_git/`, and the builtin is the command
surface over them. This page tracks what it does today, and how that is
checked.

Nothing here is copied or translated from git, which is GPL-2.0. The
formats and the protocol come from their published descriptions.

## What exists today

Phase 0, the foundation: repository discovery, the object store, refs and
the reflog, the index, trees, configuration and the plumbing commands that
exercise them. Phase 1, the everyday commands: adding, committing, looking
at what changed, branching, switching, restoring and tagging.

```
git add          [-A | -u] [-n] [-f] [--] [<pathspec>...]
git commit       [-a] [-m <message>] [-F <file>] [--amend] [--allow-empty] [-q]
git status       [-s | --short | --porcelain[=<version>]] [-b] [-u<mode>]
                 [--ignored]
git diff         [-p] [--stat] [--numstat] [--shortstat] [--summary]
                 [--name-only] [--name-status] [-s] [-U<n>] [--cached]
                 [<commit> [<commit>]] [-- <path>...]
git log          [--oneline] [--format=<format>] [-p] [--stat] [-<n>]
                 [-n <number>] [--reverse] [--first-parent] [--date=raw]
                 [<revision>...]
git show         [-p | -s | --stat] [--oneline] [--format=<format>] [<object>...]
git branch       [-v] [--show-current] [<name> [<start>]] | (-d | -D) <name>
                 | (-m | -M) <old> <new>
git switch       [-q] [-c <new>] [--detach] <branch>
git checkout     [-q] [-b <new>] <branch> | [--] <path>...
git restore      [--staged] [--worktree] [--source=<tree>] [--] <path>...
git reset        [-q] [--soft | --mixed | --hard] [<commit>] [-- <path>...]
git rm           [--cached] [-r] [-f] [-q] [--] <path>...
git mv           [-v] [-f] [-k] [-n] <source>... <destination>
git clean        [-d] [-f] [-n] [-q] [-x | -X] [--] [<path>...]
git merge-base   [--all] <commit> <commit>... | --is-ancestor <a> <b>
                 | (--independent | --octopus) <commit>...
git merge-file   [-p] [-L <label>]... <current> <base> <other>
git merge        [-m <message>] [--no-ff] [--ff-only] [--no-commit] [-q]
                 <commit> | --abort
git cherry-pick  [-n] <commit> | --continue | --abort
git stash        [push] [-m <message>] | list | show [-p] [<stash>]
                 | apply [<stash>] | pop [<stash>] | drop [<stash>] | clear
git rebase       <upstream> [<branch>] | --continue | --abort | --skip
git revert       [--no-edit] [-n] <commit> | --continue | --abort
git tag          [-a -m <message>] [-f] [<name> [<object>]] | (-d | -l) ...
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
git config       [--global | --local | --file <file>] [-z]
                 (--list | --get <key> | --get-all <key> | --unset <key>
                  | --add <key> <value> | <key> [<value>])
git update-index [--add] [--remove] [--cacheinfo <mode>,<object>,<path>]
                 [--index-info] [--] [<file>...]
git ls-files     [-s] [-z] [--] [<file>...]
git write-tree
git read-tree    <tree-ish>
git commit-tree  <tree> [(-p <parent>)...] [(-m <message>)...] [-F <file>]
git ls-tree      [-r] [-t] [-z] [--name-only] <tree-ish>
git rev-list     [--count] [-n <number>] <commit>...
git var          (GIT_AUTHOR_IDENT | GIT_COMMITTER_IDENT)
git check-ignore [-v] [--non-matching] [<pathname>...]
```

Revisions take git's suffixes: `^` and `^<n>` for a parent, `~<n>` for n
first-parent steps, `^{}` and `^{<type>}` to peel, `@{<n>}` for a ref's nth
previous value, read from its reflog, and `<rev>:<path>` for what a path
held in that revision. `log` and `rev-list` take ranges — `A..B` for what
B has and A does not, `^A` to exclude — and `log` takes a pathspec after
`--`, showing only the commits that changed something it names. `log
--graph` draws the column git draws, for a history without merges; a merge
in the walk is refused rather than drawn wrongly.

A patch is git's: the same hunks, in the same places. Myers' algorithm
decides which lines changed, each run of changes is then slid as far down
as the file allows, and the indent heuristic — git's default since 2.14 —
picks among the positions it could take, so a hunk starts where a person
would start it. Hunk headers carry the enclosing definition, two changes
closer than twice the context become one hunk, and a file that does not
end in a newline says so. `--stat` scales its graph the way git does, to
the same eighty columns.

Checked over this repository's own history — every change to seven files
across eight commits each — the patches are byte-identical to git's in 37
of 38 cases. The one difference is a tie: two equally short ways to
describe the same swap, and git keeps a different one of the two lines as
context. Both patches apply.

Global options: `-C <path>`, `-c <key>=<value>`, `--git-dir=<path>`,
`--work-tree=<path>`, `--no-pager` (accepted, nothing paginates),
`--version`, `--help` and `--list-cmds`, which prints the commands this
build has.

Configuration is read in git's order — the system file unless
`GIT_CONFIG_NOSYSTEM`, then `GIT_CONFIG_GLOBAL` or `~/.gitconfig` and
`~/.config/git/config`, then the repository's, then `-c` — with git's
syntax: subsections, a valueless key meaning true, comments, continued
lines, quoted values with escapes, and `include.path`. Writing keeps the
rest of the file as it is, and the name's case as you typed it. The
identity in a reflog entry comes from `GIT_COMMITTER_*` or `user.name` and
`user.email`.

Reads cover loose objects, every pack, and the alternates named by
`objects/info/alternates` or `GIT_ALTERNATE_OBJECT_DIRECTORIES`. A
repository can be a worktree, a linked worktree (a `.git` file), or bare.
Ref changes are made under a `.lock` file and append a reflog entry, so
git reads what bash-os writes and the other way round.

A command or option this build does not have exits 129 and says so. It is
never silently ignored.

`git merge` fast-forwards when it can, merges three ways when it cannot,
and says what it did in git's words — `Already up to date.`, `Updating
a..b` and `Fast-forward`, or `Merge made by the 'ort' strategy.` followed
by a stat. Nothing is written until every change is known to be safe, so a
merge that would overwrite an untracked file or a local change is refused
with the working tree as it was. A merge that does not settle leaves the
conflict markers in the working tree, the three sides in the index as
stages 1, 2 and 3, and `MERGE_HEAD` behind; `git status` then reports the
unmerged paths, `git add` settles one, `git commit` concludes the merge
with two parents, and `git merge --abort` puts everything back.

`git cherry-pick` and `git revert` are the same operation with the sides
swapped: both take what one commit changed against its parent and merge it
into HEAD, one forwards and one backwards. A pick keeps the original
author and message; a revert writes `Revert "<subject>"` and says which
commit it undoes. Either can conflict, and then leaves `CHERRY_PICK_HEAD`
or `REVERT_HEAD` behind for `--continue` or `--abort`, with `git status`
saying which is under way.

`git stash` keeps its stack where git keeps it: in `refs/stash`'s own
reflog, which is why `stash@{2}` is just a revision. A stash is two
commits — one for the index as it stood, one for the working tree, whose
parents are where HEAD was and that index commit — and they come out with
the same ids git's do. Applying one is a three-way merge against where it
was taken, so it can conflict like any other. Keeping untracked files
(`-u`) is refused for now rather than half-done.

`git rebase` replays what a branch has that its upstream does not, one
commit at a time, each replay being the same three-way merge a cherry-pick
makes. HEAD is detached for the replay and the branch only moves at the
end, which is why aborting leaves the branch exactly where it was. A
replay that stops writes the state into `.git/rebase-merge` under git's own
names, so `git status` reports the commands done and remaining the way git
reports them, and `--continue`, `--skip` and `--abort` pick it up.

A merge with more than one base — two branches that have already merged
each other — is refused rather than merged against one of them, because
that is not what git would do.

The three-way merge behind `merge-file` is git's: what one side changed
alone is taken, what both changed the same way is taken once, and the rest
is written between conflict markers. Two conflicts with three or fewer
settled lines between them stay as one, because moving those lines inside
costs no more lines than the markers would; and each conflict is then
refined by comparing the two sides with each other, so whatever they turn
out to agree on is settled outside the markers.

Over five hundred randomly edited three-way cases the result is identical
to git's. Where a file holds many identical lines — blank lines, repeated
boilerplate — several shortest answers exist, and bash-os may pick a
different one from git's; both describe the same edit in the same number
of lines.

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

A scenario names the commands it needs in a `# requires:` line, and whole
features — patch output, say — in a `# requires-feature:` line, checked
against `git --list-features`. A scenario is skipped while anything it
needs is missing, so scenarios for later phases can sit in the tree and
start running as soon as their commands land.

`tests/git-odb.py` checks the object store directly against `git
cat-file`: loose objects, packed ones after `git gc`, abbreviations,
`--batch-check`, a linked worktree, a bare clone, alternates, `GIT_DIR`,
and that what `obj` writes git can read.

`tests/git-sanitize.sh` builds the builtin and its helpers with ASan and
UBSan and runs a scenario shaped to reach the edges of the code that walks
memory built from file content: a four-hundred-line file changed in six
places, a file with no trailing newline, a binary file, a path that has to
be quoted, and every command that reads the working tree.

`tests/git-refs.py` checks refs from both sides: git packs its refs away
with `pack-refs`, and bash-os still resolves, lists and deletes them;
what bash-os writes — refs, a deleted packed ref, reflog entries, a
symbolic ref — git reads back, and `fsck --strict` stays clean. It also
holds a `.lock` file and checks that the update is refused with git's
message and changes nothing.

## Still to come

Merging, cherry-pick, revert, stash and rebase are in. The rest of Phase 2
is worktrees, submodules, rename detection, stashing untracked files,
interactive rebase, and a merge with more than one base. After that come HTTPS remotes with protocol v2, then SSH. The plan, including what each
phase must match, is in the implementation document for the port.
