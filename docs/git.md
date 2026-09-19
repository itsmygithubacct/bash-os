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
git worktree     add [-b <branch>] [--detach] <path> [<commit>] | list
                 [--porcelain] | remove [-f] <path> | prune
git remote       [-v] | add <name> <url> | remove <name> | set-url <name>
                 <url> | get-url <name>
git clone        [-q] [--bare] <source> [<directory>]
git fetch        [-q] [--upload-pack=<command>] [<remote>]
git pull         [<remote>]
git push         [<remote> | <path> [<branch>]]
git ls-remote    [--heads] [--tags] [--symref] [--upload-pack=<command>]
                 [<repository>]
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
git rev-list     [--count] [-n <number>] [--objects] [--all] <commit>...
git var          (GIT_AUTHOR_IDENT | GIT_COMMITTER_IDENT)
git check-ignore [-v] [--non-matching] [<pathname>...]
git pack-objects [-q] <base-name> < <object-list>
git index-pack   [-v] [-o <index-file>] <pack-file>
git unpack-objects [-q] < <pack-file>
git verify-pack  [-v] [-s] <idx-file>
git upload-pack  [--stateless-rpc] [--advertise-refs] <directory>
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

`git worktree` adds a second checkout of the same repository: a `.git`
file pointing at an administrative directory under `worktrees/`, with its
own HEAD, index and logs, and refs and objects shared through `commondir`.
The repository layer already read that arrangement — it is how a linked
worktree is found — so the command mostly writes what the reader expects,
including the two reflog entries git leaves in a new worktree's HEAD. A
branch checked out in another worktree is marked with a `+` by
`git branch`, and using it twice is refused.

Renames are found the way git finds them: a deletion and an addition are
one rename when the content is the same, or close enough. "Close enough"
is git's own measure — both files are cut into chunks, each ending at a
newline or after 64 bytes, and the score is the source's bytes that
survive in chunks the destination also has, against the larger file. Half
is the threshold, and the same number out of a hundred is the `similarity
index` a patch shows. Over a hundred and twenty randomly edited renames
the score matches git's every time. `git diff`, `git log`, `git show` and
`git status` all report renames, `--no-renames` turns it off, and a
comparison that ends at the working tree does not look for them, having
no recorded ids to compare.

Clone, fetch and pull go over the protocol, the way git goes over it even
when both repositories are directories on this machine: `upload-pack` is
started at the far end, `ls-refs` says what it has, and `fetch` asks for
what is missing here — naming what is already here, so a second fetch
carries only what the first one did not. What comes back is a packfile,
kept the way git keeps one: exploded into loose objects when it holds
fewer than a hundred, written into `objects/pack` beside a generated
index when it holds more.

A push still copies objects straight into the other store, since the
protocol for that is `receive-pack` and comes next. It may only move a
branch forward, and is refused into a branch the far end has checked out,
with git's words for both. It takes a path as readily as the name of a
remote, and records a tracking ref only for the one that has a name to
record it under. A URL is refused rather than half-attempted: the
protocols over a network are the phase after this one.

A bare clone is a different thing from a checkout without a working tree:
it is where the branches live, so git writes them as branches rather than
as tracking refs, keeps no fetch refspec, and points HEAD at the branch
the far end's HEAD named. This build does the same, and says so the way
git says it — `Cloning into bare repository '<name>'...`.

Packfiles can be made, indexed, checked and taken apart again.
`git pack-objects` reads the ids to pack from its input — `git rev-list
--objects --all` names them — and writes `<base>-<sha>.pack` beside its
`.idx`, each object whole: nothing is deltified, so the pack is larger
than git's would be, but it is a pack git reads. `git index-pack` builds
an index from a pack alone, which means resolving every delta in it, both
the kind that names its base by offset and the kind that names it by id.
An index is a function of its pack, so the two implementations must write
the same index bytes for the same pack even though they would never pack
alike, and that is what the test asks for. `git verify-pack` reads the
pack through its index and checks it end to end, and `git unpack-objects`
writes a pack's objects back out loose.

Every transport here holds a conversation rather than reading another
repository's files. The far end is started — this build's own `git
upload-pack`, or whatever `--upload-pack` names — and protocol v2 goes
over the pipe between them, as git does it: the server offers what it can
do, the client asks for one command at a time, and everything is framed
in pkt-lines, four hexadecimal digits of length and then that many bytes,
with the three lengths that carry no payload meaning the end of a
section, a divide inside one, and the end of a response.

`ls-refs` answers with the refs asked for, carrying what HEAD points at
and what a tag points at. `fetch` answers with a packfile down the first
side-band channel, holding everything the wants reach that the haves do
not; a client that says `done` gets the pack straight away, and one still
negotiating is told which of its haves are here and that this end is
ready.

Both ends stand on their own. git's client clones and fetches through
this build's `upload-pack` and gets the history it would get from git's;
this build's client fetches from either server and gets the same; and the
packets themselves match git's, request for request.

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

The reference git is whatever the machine has, and CI's is newer than this
laptop's. Where git has changed its own wording between those versions —
the line a stopped rebase ends with, the shape of a todo entry — the
comparison leaves that line out and says why, rather than pinning bash-os
to one machine's git.

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

`tests/git-packs.py` checks the pack commands against a pack real git
made, which is the only way to reach the delta reader: this build's own
packs carry no deltas. git repacks a history into one pack, and bash-os
must index it to git's index byte for byte, list it the way `verify-pack
-v` lists it — depth and base id and all — and unpack it into the same
objects. The other direction is checked too: git must index, verify and
unpack what `git pack-objects` writes here.

`tests/git-proto.py` crosses the two implementations over the wire: git
clones and fetches through this build's upload-pack, this build fetches
through git's, the packets themselves are read off the connection and
compared with the ones git sends for the same request, and the pack a
`have` produces is counted to show the far end sends only what is
missing. A scenario cannot reach that, since both of its runs speak to
their own far end.

`tests/git-refs.py` checks refs from both sides: git packs its refs away
with `pack-refs`, and bash-os still resolves, lists and deletes them;
what bash-os writes — refs, a deleted packed ref, reflog entries, a
symbolic ref — git reads back, and `fsck --strict` stays clean. It also
holds a `.lock` file and checks that the update is refused with git's
message and changes nothing.

## Still to come

Phase 2 is done but for submodules, and Phase 3 is under way: clone,
fetch and pull speak protocol v2 to a far end started at a path, not yet
to a URL. Next is `receive-pack`, so that a push goes the same way, and
then the same conversation over HTTPS; after that SSH. `git fetch` still
wants the name of a remote where git also takes a path, which needs
`FETCH_HEAD` to mean anything.

Left over from Phase 2: stashing untracked files, interactive rebase,
renames between the index and the working tree, and a merge with more
than one base. The plan, including what each phase must match, is in the
implementation document for the port.
