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
git commit       [-a] [-m <message>] [-F <file>] [--amend] [--allow-empty]
                 [-e | --no-edit] [-q] [-S[<key>]] [--no-gpg-sign]
git status       [-s | --short | --porcelain[=<version>]] [-b] [-u<mode>]
                 [--ignored]
git diff         [-p] [--stat[=<width>[,<name>[,<count>]]]] [--numstat]
                 [--shortstat] [--summary]
                 [--name-only] [--name-status] [-s] [-U<n>] [--cached]
                 [--stat-width=<n>] [--stat-name-width=<n>]
                 [--stat-graph-width=<n>] [--stat-count=<n>]
                 [<commit> [<commit>]] [-- <path>...]
git log          [--oneline] [--format=<format>] [-p] [--stat] [-<n>]
                 [-n <number>] [--reverse] [--first-parent]
                 [--date=<format>] [--decorate[=short|full|auto|no]]
                 [--show-signature] [--grep=<pattern>] [--author=<pattern>]
                 [--committer=<pattern>] [-i] [-E] [-F] [--invert-grep]
                 [--all-match] [--merges | --no-merges]
                 [--min-parents=<n>] [--max-parents=<n>]
                 [--since=<date>] [--until=<date>] [<revision>...]
git show         [-p | -s | --stat] [--oneline] [--format=<format>]
                 [--date=<format>] [--decorate[=short|full|auto|no]]
                 [--show-signature] [<object>...]
git branch       [-v] [--show-current] [<name> [<start>]] | (-d | -D) <name>
                 | (-m | -M) <old> <new>
git switch       [-q] [-c <new>] [--detach] <branch>
git checkout     [-q] [-b <new>] <branch> | [--] <path>...
git restore      [--staged] [--worktree] [--source=<tree>] [--] <path>...
git reset        [-q] [--soft | --mixed | --hard] [<commit>] [--] [<path>...]
git rm           [--cached] [-r] [-f] [-q] [--] <path>...
git mv           [-v] [-f] [-k] [-n] <source>... <destination>
git clean        [-d] [-f] [-n] [-q] [-x | -X] [--] [<path>...]
git merge-base   [--all] <commit> <commit>... | --is-ancestor <a> <b>
                 | (--independent | --octopus) <commit>...
git merge-file   [-p] [-L <label>]... <current> <base> <other>
git merge        [-m <message>] [--no-ff] [--ff-only] [--no-commit]
                 [-e | --no-edit] [-q] <commit> | --abort
git cherry-pick  [-n] <commit> | --continue | --abort
git submodule    [status [--cached]] | init | update [--init] [-q]
                 | add <url> [<path>] | deinit [-f] [--all]
                 | foreach [-q] <command> [<path>...]
git stash        [push] [-m <message>] [-u] | list | show [-p] [<stash>]
                 | apply [<stash>] | pop [<stash>] | drop [<stash>] | clear
git rebase       [-i] [-r | --rebase-merges[=(no-)rebase-cousins]]
                 [--update-refs] <upstream> [<branch>]
                 | --continue | --abort | --skip
git worktree     add [-b <branch>] [--detach] <path> [<commit>] | list
                 [--porcelain] | remove [-f] <path> | prune
git remote       [-v] | add <name> <url> | remove <name> | set-url <name>
                 <url> | get-url <name>
git clone        [-q] [--bare] [-n|--no-checkout] [-b|--branch <name>]
                 [-o|--origin <name>] <path> | <http url> [<directory>]
git fetch        [-q] [-p|--prune] [-t|--tags] [--upload-pack=<command>]
                 [<remote> | <path> [<refspec>...]]
git pull         [-q] [--ff-only] [--no-ff] [--rebase]
                 [<remote> | <path> [<refspec>...]]
git push         [-q] [-f|--force] [--delete] [--tags] [-n|--dry-run]
                 [-u|--set-upstream] [--receive-pack=<command>]
                 [<remote> | <path> [<refspec>...]]
git ls-remote    [--heads] [--tags] [--symref] [--upload-pack=<command>]
                 [<repository>]
git revert       [--no-edit] [-n] <commit> | --continue | --abort
git tag          [-a] [-s] [-u <key>] [-m <message>] [-f] [<name>
                 [<object>]] | (-d | -l) ...
git init         [-q] [--bare] [-b <branch>] [<directory>]
git rev-parse    [--git-dir] [--absolute-git-dir] [--show-toplevel]
                 [--is-inside-work-tree] [--is-bare-repository]
                 [--abbrev-ref] [--short[=N]] [--symbolic-full-name]
                 [--all] [--branches] [--tags] [--remotes]
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
git ls-files     [-c] [-d] [-m] [-o] [-i] [-u] [-t] [-s] [-z]
                 [--directory] [--exclude-standard] [--] [<file>...]
git write-tree
git read-tree    <tree-ish>
git commit-tree  <tree> [(-p <parent>)...] [(-m <message>)...] [-F <file>]
git ls-tree      [-d] [-r] [-t] [-l] [-z] [--name-only] [--abbrev=<n>]
                 <tree-ish> [<path>...]
git rev-list     [--count] [-n <number>] [--objects] [--parents] [--all]
                 [--grep=<pattern>] [--author=<pattern>] [--merges]
                 [--no-merges] [--since=<date>] [--until=<date>]
                 <commit>...
git var          (GIT_AUTHOR_IDENT | GIT_COMMITTER_IDENT)
git check-ignore [-v] [--non-matching] [<pathname>...]
git pack-objects [-q] <base-name> < <object-list>
git index-pack   [-v] [-o <index-file>] <pack-file>
git unpack-objects [-q] < <pack-file>
git verify-pack  [-v] [-s] <idx-file>
git verify-commit [-v | --verbose] [--raw] <commit>...
git verify-tag   [-v | --verbose] [--raw] <tag>...
git upload-pack  [--stateless-rpc] [--advertise-refs] <directory>
git receive-pack <directory>
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

One difference remains, and only on large changes. git's search gives up
when it grows expensive — it cuts at the furthest point it has reached
and carries on from there — so on a big rewrite it settles for a patch
that is a few lines longer than the shortest one. The search here always
finds the shortest. Over a hundred and twenty commits of this project's
own history, a hundred and ten patches come out byte for byte the same;
of the ten that differ, five are the same length with a run of changes
placed differently, and in five git's is the longer. Nothing about either
is wrong — both describe the same change — but they are not the same
bytes, and matching git there means keeping its cost heuristic as well as
its algorithm.

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
lines, quoted values with escapes, and `include.path`. A section and a
variable are matched without regard to case, and the subsection between
them exactly, as git matches them. Writing keeps the
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

Which of the commits found are shown is git's own set of filters, and
`git rev-list` takes them too: `--grep=`, `--author=` and `--committer=`
are basic regular expressions over the message and over "Name <email>",
with `-E` for the wider ones, `-F` for a pattern that stands for itself,
`-i` to ignore case, `--invert-grep` and `--all-match`; `--merges`,
`--no-merges`, `--min-parents=` and `--max-parents=` count parents; and
`--since=` and `--until=` take a date. A date is read the way git reads
one — `@<seconds>`, a day or a moment written out, and the common
relative forms — and what it leaves unsaid is filled in from the present
moment, so a bare day means that day at this time of it. A month there is
thirty days and a year three hundred and sixty-five, and a date this
build cannot place is taken for the present moment, which is what git
does with one it cannot place either.

A subject is the message down to its first blank line, with the breaks
inside it written as single spaces and the whitespace at each line's end
dropped, and the body is what follows that blank line: `%s`, `%b` and the
one-line form all read them that way.

An ignore rule that excludes a directory excludes everything under it,
and nothing below can be brought back: `git check-ignore -v` names that
rule for a path inside such a directory, as git names it. A directory
whose content is ignored to the last file is itself what
`git status --ignored` reports, while an ignored file inside an untracked
directory is named on its own — and a `.gitignore` deeper down is read as
the walk reaches it.

A stat is drawn to whatever `--stat=<width>[,<name-width>[,<count>]]` asks
for, or the same in `--stat-width=`, `--stat-name-width=`,
`--stat-graph-width=` and `--stat-count=`: a name too long for its column
is cut from the left at a directory boundary and written with a leading
`...`, and the files past `<count>` are one `...` line of their own, with
the summary underneath still counting them all.

`git ls-files` answers with what the index holds, and with `-m`, `-d` and
`-o` what has changed, gone, or was never taken in — the last of those
listed one file at a time, or one directory at a time with `--directory`,
and filtered through the ignore rules only when `--exclude-standard` says
to. `-i` narrows any of them to what those rules cover, and is refused
without `-o` or `-c` to narrow, as git refuses it. `-t` puts git's letter
in front of each line — `H` held, `C` changed, `R` removed, `?` untracked,
`M` unmerged — and `-s` writes the index's own record of the path, which
is also what `-u` writes for each side of a path a merge did not settle.

`git ls-tree` reads one level at a time, going below only where `-r` says
to or where a path named on the command line leads. A path written with a
trailing slash names what is inside that tree rather than the tree itself,
`-d` keeps the trees alone, `-l` adds each blob's size, and `--abbrev=<n>`
shortens the ids.

An ignore rule decides what `git add` takes in, and has nothing to say
about what is in already: a tracked path is staged however the rules read,
which is what git does, and `-f` takes in an ignored one. `git reset`
takes a path where a revision would go — `git reset <file>` is how a
staged change is put back — lists what it left between the index and the
files under "Unstaged changes after reset:", and says where a `--hard`
landed. Before the first commit HEAD stands for the empty tree, so a reset
then empties the index rather than complaining that HEAD is not a
revision.

`git log` writes a date the way `--date=` asks for it: `default`, `raw`,
`iso`, `iso-strict`, `short`, `unix`, `rfc`, `relative`, and a `format:`
pattern of the caller's own, each of them also with a `-local` suffix that
reads the time off the clock in front of the reader instead of the one the
commit recorded. `%ad` and `%cd` follow that option, while `%at`, `%ai`,
`%aI`, `%as` and `%ar` each name a mode of their own. The two modes that
count from the moment of the run are `relative`, which is written, and
`human`, which is not.

The names that point at a commit go where git puts them: `--decorate`
after the id, `--decorate=full` with every ref written out whole, and with
neither option a terminal is decorated and a pipe is not, which is what
`auto` means. `%d` and `%D` carry the names whatever `--decorate` says,
since a format that asks for them has asked already. What HEAD stands on
comes first, as `HEAD -> <branch>`, and the rest follow in git's own
order.

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

With no `-m` and no `-F`, the message is written in an editor, which is
`GIT_EDITOR`, then `core.editor`, then `VISUAL`, then `EDITOR`, and `vi`
when nothing names one; `:` does nothing, as it does for git. What the
editor is given is git's own template — the two lines about what will be
ignored, who wrote it when that is not who is committing it, the date
when a commit is being amended, and the status underneath, every line
behind a `#` — and what comes back is the message with those lines taken
out. An empty message is `Aborting commit due to empty commit message.`
and nothing committed. `-e` opens the editor over what `-m` said; a
merge starts from `MERGE_MSG`, and `--no-edit` takes it as it stands.
`git tag -a` is written the same way, over git's note, and an empty one
is `fatal: no tag message?`.

`git stash` keeps its stack where git keeps it: in `refs/stash`'s own
reflog, which is why `stash@{2}` is just a revision. A stash is two
commits — one for the index as it stood, one for the working tree, whose
parents are where HEAD was and that index commit — and they come out with
the same ids git's do. Applying one is a three-way merge against where it
was taken, so it can conflict like any other, and a pop that conflicts
keeps the entry and says so.

`-u` takes what is not tracked yet along with the rest. Those files
become a third commit with no parent of its own — `untracked files on
<branch>: …` — standing as the stash's third parent, which is how git
marks that it has them; they then leave the working tree, and a
directory left empty goes with them. An ignored file is not one of
them. Popping puts them back where nothing stands in their way, and
where something does it says `<path> already exists, no checkout`,
leaves that file alone and keeps the entry. Even a pop whose tracked
half is refused puts the untracked half back and says where it stands,
which is what git does.

A repository that holds another one is read the way git reads it. The
index entry for a submodule is a commit id, not a file: what the
repository over there has checked out is what the entry is held against,
the directory itself is never read, and nothing inside it is this
repository's business — not as untracked files, and not when `git add`
names the path, which stages the commit that submodule has now. `status`
says which kind of change it is, as git does: `M` for a commit that
moved, `m` for content of its own that changed, `?` for nothing but
untracked files in it; the long form spells the same out after the name
— `(new commits, modified content, untracked content)` — and
`--porcelain=v2` carries git's `S<c><m><u>` field. A `diff` shows a
submodule the way git shows one, as the `Subproject commit` line
changing. A submodule that was never cloned has nothing to say, which is
also git's answer.

`git rebase -i` writes the list of what it is about to replay, hands it
to the sequence editor — `GIT_SEQUENCE_EDITOR`, then `sequence.editor`,
then the ordinary editor — and does what comes back. The list is git's,
down to the note under it, and the commands are `pick`, `reword`,
`edit`, `squash`, `fixup`, `exec`, `break` and `drop`, in full or by
their first letter. A line struck out drops that commit; lines moved
about are replayed in the order they are in; a list with nothing left in
it is `error: nothing to do` and the branch is untouched. `reword` and
`squash` ask for the message in the editor, over git's note about what
is being combined and where the rebase stands. `edit` stops with git's
words about amending, and `git rebase --continue` then folds whatever
was staged into that commit, asking for the message as git asks. `exec`
runs its line through this build's own shell — a machine with no other
one can still rebase — and a failure stops the rebase with git's
warning.

A commit that already stands where it would land is moved to rather than
replayed, as git does: the run of them at the start is stepped over in
one go, which is why a rebase that changes nothing says nothing at all,
and each one after that is a `rebase: fast-forward` in the log.

A plain rebase replays what one branch did, and a merge did none of it:
the merges are left out and what they brought in is replayed on its own,
in the order git replays it — by date, then set so that nothing stands
before a commit it descends from.

`git rebase -r`, or `--rebase-merges`, keeps them instead. It writes a
list of another shape: `label onto` for the commit the rebase lands on,
then a section for each branch that was merged in — a `# Branch <name>`
comment, a `reset` to where it grew from, its commits, and a `label`
naming its tip — and then the branch being rebased, whose merges are
`merge -C <commit> <label>` lines. The names come from the merge
messages, as git's do: `Merge branch 'side'` gives `side`, a pull
request gives what stands after `from`, anything else gives the whole
subject, with everything that is not a letter or a digit turned into a
dash and a number added when two would be called the same. A commit two
branches grew from is labelled `branch-point`. A branch that grew from
further back than this rebase itself keeps where it was, unless
`--rebase-merges=rebase-cousins` says to move it onto the new base too.
The labels are refs under `refs/rewritten` while the rebase runs, and go
when it finishes or is called off.

`--update-refs`, or `rebase.updateRefs`, carries the other branches
along: every branch standing on a commit about to be replayed gets an
`update-ref` line after that commit's pick, and each one is moved to
where its commit ended up. The moves happen when the whole rebase is
done, not as it goes, so a rebase that stopped and was taken up again
still knows about them — they are written down in
`.git/rebase-merge/update-refs`, three lines to a branch, the way git
writes them. Each branch moved says `rewritten during rebase` in its
reflog, and at the end the rebase lists what it moved.

The three commands can also be written by hand in any `-i` list. `label`
names where HEAD stands, `reset` comes back to a name or a commit, and
`merge` merges a label in — reusing the message and author of the merge
it is replaying, moving to that merge when nothing about it has changed,
and otherwise held against the base the two sides share, made up from
several where there are several. A merge that does not settle stops the
rebase with `Could not apply`, leaves `MERGE_HEAD` behind, and
`git rebase --continue` then asks for the message and makes the merge
commit, exactly as git does.

`git submodule` covers what a checkout needs and what putting one
together needs. `status` says
where each one stands: a minus for one with nothing checked out, a plus
for one whose commit is not what the index records, and after the path
what `describe` would call that commit — `heads/main`, or
`heads/main-2-g1234567` when it is not a ref's own tip. `init` resolves
the url `.gitmodules` gives — a relative one against `remote.origin.url`,
or against this repository when it has none, which git warns about and
so does this — and writes it into this repository's configuration, where
`update` reads it. `update` fetches what is missing, puts its git
directory where git puts one (`.git/modules/<name>`, with a `.git` file
in the submodule naming it) and moves it to the commit the index
records; `--init` does the registering on the way. A second `update`
with nothing to do says nothing, as git's does. The url may be a path or
an address this build can reach; the nested commands run as this build's
own git, in a child of their own.

`add` takes a repository in: it clones it where it is to live, puts its
git directory under `.git/modules`, writes the name, path and url into
`.gitmodules` — the url as it was given, relative and all — says here
where that really points, and stages both the file and the gitlink.
`deinit` is the other way round: the working tree of the submodule is
emptied and this repository forgets where it came from, while what is
under `.git/modules` stays, so a later `update` puts it back without
fetching anything. A submodule with changes of its own is not let go of
without `-f`, in git's words. `foreach` runs a command in each submodule
that is there, with `$name`, `$sm_path`, `$displaypath`, `$sha1` and
`$toplevel` set as git sets them, saying `Entering '<path>'` first unless
told to be quiet, and stopping at the first command that fails.

`git add` stages a directory that holds a repository of its own as the
commit it stands at — a gitlink — and says what git says about adding an
embedded repository, unless `--no-warn-embedded-repo` says not to, which
is what `submodule add` passes. A gitlink is not an object of this
repository, so `rev-list --objects` leaves it out, as git's does.

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
comparison that ends at the working tree looks for them too — what is
there has been hashed but not written down, so the files themselves are
read to weigh a pairing. A path renamed in the index and edited since is
`RM`, as git writes it.

Clone, fetch and pull go over the protocol, the way git goes over it even
when both repositories are directories on this machine: `upload-pack` is
started at the far end, `ls-refs` says what it has, and `fetch` asks for
what is missing here — naming what is already here, so a second fetch
carries only what the first one did not. A fetch takes the refspecs it
was given or the one the remote is configured with, `--prune` to drop
what the far end no longer has, and `--tags` for every tag; the tags that
point at what it fetched come with it either way, which is what
`include-tag` asks for. What came over is written into `FETCH_HEAD`,
with the one the branch follows marked for merging and the rest not.

The remote can be a path or a URL rather than a name, and then there is
nowhere for what it brings to land: there are no remote-tracking refs for
something that is not a remote, so it goes into `FETCH_HEAD` and nowhere
else — whatever the far end has checked out when nothing was asked for,
and otherwise the branches and tags named, each one left for a merge to
take. Naming `FETCH_HEAD` afterwards means the first line of it, which is
how git reads it too, so `git merge FETCH_HEAD` and `git log FETCH_HEAD`
say what they say in git. No tag comes along uninvited that way, which is
also git's rule.

`git pull` is a fetch and then one of two things: a merge, or — with
`--rebase`, or `pull.rebase` — this branch replayed on what came over.
It passes on what it was given, so `git pull <path> <branch>` fetches
that branch from there and joins it. What a merge joins is what the fetch
wrote down, which is why the merge says where it came from —
`Merge branch 'main' of ../far` — and what a replay goes onto is the
branch this one follows, when there is one.
`--ff-only` refuses anything but a fast-forward, in git's words, and
`pull.ff = only` says the same thing standing. What comes back is a packfile,
kept the way git keeps one: exploded into loose objects when it holds
fewer than a hundred, written into `objects/pack` beside a generated
index when it holds more.

A push is the same conversation the other way round, in the protocol git
still uses for it: `git receive-pack` sends out the refs this repository
has and what it can do, the pushing end sends the change it wants and a
pack, and the report says what became of it. Both halves are here, so
this build pushes into git and git pushes into this build. The far end
refuses a branch it has checked out, one whose old id is not what the
pusher thought, and one whose objects did not arrive, each in git's
words; a push that would lose commits is the pushing end's to refuse,
and the far end allows one unless `receive.denyNonFastForwards` says
otherwise, which is git's rule; what it says for itself goes down the
second side-band channel, which is what puts `remote:` in front of every
line of it. A pack whose deltas lean on objects it does not
carry — which is what git sends when the far end already has them — is
completed from what is here, so a second push of a large file that
changed in one place carries the change and not the file.

A push says what it wants as refspecs: `<branch>` for the obvious thing,
`<src>:<dst>` to land it under another name, `+<src>:<dst>` or `--force`
to move a ref that would otherwise lose commits, and `:<dst>` — or
`--delete <dst>` — to unmake one. `--tags` adds every tag this
repository has, `-u` makes the branch follow where it was pushed, and
`--dry-run` says what all of that would do without doing any of it.

The pushing end refuses two things before it sends anything, the way git
does, and tells them apart the way git does: a tip it has never seen
wants fetching first, and one it has seen but not built on would lose
commits. A push may only move a branch forward, and is refused into a branch the far end has checked out,
with git's words for both. It takes a path as readily as the name of a
remote, and records a tracking ref only for the one that has a name to
record it under. A URL is refused rather than half-attempted: the
protocols over a network are the phase after this one.

A clone takes the branch it was asked for with `-b`, leaves the working
tree alone with `--no-checkout`, and calls the remote what `--origin`
says rather than `origin`. A branch the far end has not got is refused
in git's words, before anything is written.

A bare clone is a different thing from a checkout without a working tree:
it is where the branches live, so git writes them as branches rather than
as tracking refs, keeps no fetch refspec, and points HEAD at the branch
the far end's HEAD named. This build does the same, and says so the way
git says it — `Cloning into bare repository '<name>'...`.

Packfiles can be made, indexed, checked and taken apart again.
`git pack-objects` reads the ids to pack from its input — `git rev-list
--objects --all` names them — and writes `<base>-<sha>.pack` beside its
`.idx`. An object that is nearly the same as one already written goes in
as the difference between them rather than whole. Which objects those
are is a matter of order: like with like, then by the path each was
found at hashed the way git hashes it, then the larger first, and within
all that the order the history was walked in — so one revision of a file
or a tree sits next to the one before it. Each object is then held
against the ten written before it, and the smallest difference wins, so
long as it is under half the object and the chain it joins is under
fifty long. A pack written here names a delta's base by how far back it
is; a pack sent over the wire names it by id, which needs nothing agreed
between the two ends. `git index-pack` builds
an index from a pack alone, which means resolving every delta in it, both
the kind that names its base by offset and the kind that names it by id.
An index is a function of its pack, so the two implementations must write
the same index bytes for the same pack even though they would never pack
alike, and that is what the test asks for. `git verify-pack` reads the
pack through its index and checks it end to end, and `git unpack-objects`
writes a pack's objects back out loose.

Every transport here holds a conversation rather than reading another
repository's files. For a path the far end is started — this build's own
`git upload-pack`, or whatever `--upload-pack` names — and protocol v2
goes over the pipe between them; for an `http://` or `https://` address
the same packets go in the body of a request, which is what git calls
smart HTTP. Either way the shape is git's: the server offers what it can
do, the client asks for one command at a time, and everything is framed
in pkt-lines, four hexadecimal digits of length and then that many bytes,
with the three lengths that carry no payload meaning the end of a
section, a divide inside one, and the end of a response.

An advertisement over HTTP may open by naming the service before it says
what the far end can do, with a flush between the two; git's own backend
leaves that line out and the large forges put it in, so both are read.

`ls-refs` answers with the refs asked for, carrying what HEAD points at
and what a tag points at. `fetch` answers with a packfile down the first
side-band channel, holding everything the wants reach that the haves do
not; a client that says `done` gets the pack straight away, and one still
negotiating is told which of its haves are here and that this end is
ready.

Over HTTP a conversation is a request at a time: the refs come from a
`GET` of `info/refs`, and each command after that is a `POST` whose body
is the packets that would have gone down the pipe. `curl` does the
talking — the builtin when this build has it, and the command otherwise,
which is how `pkg` fetches — so TLS, and everything else about reaching
a host, is settled in one place. What comes back is read from memory
rather than from a descriptor, which the pkt-line reader does either way.
A far end that asks for a name and secret is answered from the file
`credential.helper store` keeps them in, after the first request comes
back without one — which is when git asks too. With nothing to answer
with, it says so in git's words rather than waiting for a terminal it
has not got. `http.extraHeader` is said with every request, and a
redirect is followed on the first request and no other, which is what
git means by `http.followRedirects = initial`.

Both ends stand on their own. git's client clones and fetches through
this build's `upload-pack` and gets the history it would get from git's;
this build's client fetches from either server and gets the same; it
clones, fetches and pushes over HTTP against git's own `http-backend`;
and the packets themselves match git's, request for request.

Over ssh the same conversation runs through a command on another
machine: `ssh://[user@]host[:port]/path` and the scp-style
`[user@]host:path` both name one, and what runs there is
`git-upload-pack '<path>'` or `git-receive-pack '<path>'`, the path
quoted for the far end's shell. Which ssh is used is `GIT_SSH_COMMAND`,
then `core.sshCommand`, and with neither this build's own — `ssh run`,
which needs no PATH and no other program on the machine. A command that
is named is treated as git treats one: this build tells one ssh from
another by what it is called, the one called `ssh` is given
`-o SendEnv=GIT_PROTOCOL` so the far end learns which protocol version
is meant and `-p` for a port, and anything else is handed the host and
the command and nothing besides — asking such a command for a port is
refused in git's words. The builtin is told the same things in its own
terms: `--setenv GIT_PROTOCOL=version=2` and `-p`. A bracketed address —
`[2001:db8::1]:repo.git` — keeps its own colons, and a path that begins
with `~` is left for the far end's shell to expand.

`ssh run [user@]host <command>` is what carries it: one command on
another machine with this process's own input and output on it, and the
remote command's own status at the end. That is what a protocol needs
and what `ssh exec` — which hands over a file and collects two blobs —
cannot do. With no `-i`, the keys everybody keeps under `~/.ssh` are
tried in ssh's order. The `sshd` builtin hosts the same conversation
from the other side: a command it runs has the channel on its streams
rather than being run to completion and reported afterwards, so it can
answer a client that is waiting to hear before it speaks again.

Both ends work over it: this build clones, fetches and pushes through
git's `git-upload-pack` and `git-receive-pack`, and git clones and
pushes through this build's. The far end must be told `GIT_PROTOCOL`,
since this build speaks version 2 only; that is what `SendEnv` is for,
and it needs the server to accept it — `AcceptEnv GIT_PROTOCOL` in
sshd's configuration, which OpenSSH and this build's `sshd` both read.

With nothing else on the machine the whole of it is this build: the
`git` builtin reaching out, the `ssh` builtin carrying it, the `sshd`
builtin hosting it, and a far end at the other end. The test does
exactly that, over the loopback address.

A commit or a tag can be signed with an ssh key, which is what
`gpg.format = ssh` asks for: `user.signingKey` names the private key,
`-S` or `commit.gpgsign` signs a commit, and `-s` or `tag.gpgSign` signs
a tag. The signature is OpenSSH's SSHSIG over the object as it would be
without one, armoured and written where git writes it — a `gpgsig`
header in a commit, after the message in a tag. git reads both back and
says `Good "git" signature`, which is what the test asks it to do.

The reading goes the other way too. `git verify-commit` and `git
verify-tag` take a signature back out of the object — a `gpgsig` header
in a commit, the block after the message in a tag — check it against
what the object says without it, and name the key by the SHA-256
fingerprint `ssh-keygen -l` would print for it. Whether that key is
anybody is a separate question, and `gpg.ssh.allowedSignersFile`
answers it: a key that stands in that file is reported as `Good "git"
signature for <principal>`, and one that does not is still a good
signature but matches no principal, which leaves with 1. `-v` prints
what was signed, and `--show-signature` sets the same lines under the
commit line in `log` and `show`. An unsigned commit is not a bad one:
git says nothing about it and leaves with 1, and so does this.

Where git leans on `ssh-keygen` for the check it also passes on what
`ssh-keygen` said about a file it could not read; this build says only
`No principal matched.` Every other line is git's, word for word, and
the test holds the two outputs against each other.

Only unencrypted ed25519 keys are signed with: one that wants a
passphrase has nowhere here to ask for it, and says so rather than
leaving something that will not verify. A signature of another kind —
an OpenPGP one, which git would hand to `gpg` — is not checked here and
says so rather than passing or failing it.

Two branches that have already merged each other have more than one
merge base, and neither on its own is what the next merge should be held
against. They are merged into a base of this build's own making —
conflicts and all, which is what git's `ort` puts in its own — and the
merge is then held against that. A commit that comes out of a
criss-cross is git's, id for id. Where there are more than two bases
they are folded in one at a time, each fold standing as a commit so the
next base has something to be held against.

A merge into a branch that is not `master` or `main` says so in its
subject — `Merge branch 'side' into topic` — which is git's rule, and
`-e` writes the message in the editor over what the merge would have
said by itself.

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
made: git repacks a history into one pack, and bash-os must index it to
git's index byte for byte, list it the way `verify-pack -v` lists it —
depth and base id and all — and unpack it into the same objects. The
other direction is checked too, deltas included: git must index, verify
and unpack what `git pack-objects` writes here, and its index of it must
be the one this build wrote.

`tests/git-proto.py` crosses the two implementations over the wire: git
clones and fetches through this build's upload-pack, this build fetches
through git's, git pushes into this build's receive-pack and this build
pushes into git's — a new branch, a fast-forward, a delete, a push with
nothing to say, a push that would otherwise be thin, and the three that
must be refused — the packets themselves are read off the connection and
compared with the ones git sends for the same request, and the pack a
`have` produces is counted to show the far end sends only what is
missing. A scenario cannot reach any of that, since both of its runs
speak to their own far end.

`tests/git-http.py` runs git's `http-backend` behind a small server on
the loopback address and does the lot over it: listing refs, cloning,
fetching what the far end has gained, pushing back, a history too big to
explode arriving as a pack, an address with no repository behind it, and
a far end that wants a name and secret — without one, with the right one
and with the wrong one. Nothing outside the machine is contacted.

`tests/git-ssh.py` ends by running a clone, a fetch and a push over the
`ssh` builtin to the `sshd` builtin on the loopback address, with a key
it makes for the occasion — no stand-in anywhere, and a live stream in
both directions. Before that it runs the transport with a stand-in named
`ssh`: it
takes the arguments git's ssh takes, writes down the line it was given,
and runs the command here rather than there. Each shape of address is
handed to both implementations and the two lines are held against each
other, word for word; then a clone, a fetch and a push go through it to
git's far end, and a clone and a push come back the other way through
this build's. Nothing outside the machine is contacted, and no server is
needed.

`tests/git-signing.py` signs a commit and a tag with a key `ssh-keygen`
made, and hands them to git's own `verify-commit` and `verify-tag` with
the key in an allowed-signers file: a signature is worth what somebody
else makes of it. It also checks that a key nobody vouches for is
refused, and that what this build cannot sign with — no key named, a
format it has not got, a key behind a passphrase — is said rather than
half-done. Then back the other way: what git signed is checked here, and
this build's `verify-commit`, `verify-tag` and `log --show-signature`
are held against git's own output — the good signature, the key's
fingerprint as `ssh-keygen -l` prints it, a message changed under its
signature, a key nobody vouches for, an unsigned commit, and a name that
is the wrong kind of object or nothing at all.

`bench/git-scale.py` builds a repository of a few thousand files and a
few thousand commits and runs each command through both implementations.
On four thousand files and twenty thousand commits this build's `log
--oneline` is 1.2 times git's time, `rev-list --count` 1.1, `diff` 2.3,
`status` and `add` about 3, and the peak memory is git's to the megabyte.
A clone over the protocol writes a pack within a megabyte of git's — 12
against 11 — in 1.35 times git's time, most of which is the window of
ten that finds the deltas.

Against a real forge rather than a repository on this machine: cloning
this project from GitHub over HTTPS takes 3.4 seconds where git takes
1.8, for the same ten-megabyte pack, and `fsck --strict` is clean. The
difference is not the work but the order of it — git indexes the pack as
it arrives, where this build reads the whole answer and then indexes it,
which costs the half second indexing takes. Indexing that pack, with
delta chains twenty-nine deep, is 0.56 seconds against git's 0.45 and
writes git's index byte for byte; checking the tree out afterwards is
0.19.

`tests/git-refs.py` checks refs from both sides: git packs its refs away
with `pack-refs`, and bash-os still resolves, lists and deletes them;
what bash-os writes — refs, a deleted packed ref, reflog entries, a
symbolic ref — git reads back, and `fsck --strict` stays clean. It also
holds a `.lock` file and checks that the update is refused with git's
message and changes nothing.

## Still to come

All four phases of the port are in, and so is what each of them named:
the everyday commands, history editing, remotes over a path and over
HTTP, and ssh and signing.

What is left out was left out on purpose. A repository whose objects are
named by SHA-256 is refused rather than half read. `git://` is not spoken
at all, and neither is dumb HTTP. Reftable, partial clones, sparse
checkouts, the split index, attributes and the filters that go with them
(end-of-line conversion, LFS), `add -p` and GPG signatures — as against
the ssh signatures this build does make and check — are all outside what
this port set out to do.

The plan, including what each phase must match, is in the implementation
document for the port.
