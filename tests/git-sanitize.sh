#!/usr/bin/env bash
# The git builtin and its helpers under ASan and UBSan. The line diff, the
# patch writer and the index and tree readers all walk memory they built
# from file content, so they are exercised here with the shapes that reach
# the edges: a long file changed in many places, a file with no trailing
# newline, a binary file, a path that has to be quoted, and every command
# that reads the working tree.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
[[ -d $BT ]] || { echo 'git-sanitize: build tree missing; run ./build.sh first'; exit 1; }
target=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" git >/dev/null
HB="$d/helpers/builtins"

"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -I"$HB" -Iloadables/common \
  loadables/git.c "$HB"/_git_*.c -lz -lm -o "$d/git.so"

repo=$d/repo
mkdir -p "$repo"
cat > "$d/scenario.sh" <<'SCENARIO'
set -e
enable -f "$GIT_SO" git
git init -q -b main .

# A long file, so the diff has real work to do, changed in several places.
: > long.txt
for i in {1..400}; do printf 'line %d of the long file\n' "$i" >> long.txt; done
printf 'no newline here' > ragged.txt
printf 'binary\000content\000here\n' > blob.bin
printf 'x\n' > 'a path with spaces and "quotes".txt'
mkdir -p nest/deeper
printf 'nested\n' > nest/deeper/file.txt
git add .
git commit -q -m 'the first commit'

for i in 7 61 199 200 201 398; do
  sed -i "${i}s/.*/line $i changed, and lengthened a little/" long.txt
done
printf 'line 401 appended\n' >> long.txt
printf 'no newline here either, but different' > ragged.txt
printf 'binary\000other\000bytes\n' > blob.bin
git diff
git diff --stat
git diff --numstat
git diff --shortstat
git diff -U0
git diff -U7
git diff --name-status
git status
git status --short
git status --porcelain=v2 --branch
git add -A
git diff --cached
git commit -m 'the second commit'
git log -p
git log --stat
git log --oneline -p
git show
git show HEAD~1
git show 'HEAD:long.txt' > /dev/null
git show 'HEAD:'
git show HEAD^{tree} > /dev/null

# Branching, switching and resetting, which rewrite the working tree.
git branch topic
git switch -q topic
printf 'on the topic branch\n' > topic.txt
git add topic.txt
git commit -q -m 'a topic commit'
git switch -q main
git diff main topic
git diff --stat main topic
git reset -q --hard HEAD~1
git status
git checkout -q topic -- topic.txt || true
git restore --staged . || true
git tag -a v1 -m 'a tag'
git show v1 > /dev/null
git rm -q --cached ragged.txt
git status --short

# A path the index holds and no commit does, taken back out of the index by
# each of the commands that do it, and pathspecs that name nothing.
printf 'only in the index\n' > staged-only.txt
git add staged-only.txt
git reset staged-only.txt
git add staged-only.txt
git restore --staged staged-only.txt
git add staged-only.txt
git restore --staged --worktree staged-only.txt
git reset -- nosuchpath
git restore --staged nosuchpath 2>/dev/null || true
git checkout HEAD -- nosuchpath 2>/dev/null || true
rm -f staged-only.txt

# Run from a directory inside the working tree, where a path is written
# from there and what is listed is what is under it.
cd nest
git status --short > /dev/null
git status --porcelain=v2 > /dev/null
git rev-parse --show-prefix > /dev/null
git ls-files > /dev/null
git ls-files --full-name > /dev/null
git ls-files ../blob.bin > /dev/null
git ls-tree -r HEAD > /dev/null
git diff --relative > /dev/null
git diff --relative --stat > /dev/null
git grep -n nested > /dev/null || true
git log --oneline -- deeper > /dev/null
printf 'from inside\n' > inside.txt
git add inside.txt
git reset inside.txt > /dev/null
git checkout -- deeper/file.txt
rm -f inside.txt
cd ..

# Moving tracked paths and sweeping untracked ones.
git mv long.txt renamed-long.txt
git mv -n renamed-long.txt nest/
git mv renamed-long.txt nest/
git mv nest/deeper other-deeper
git status --short --no-renames
printf 'sweep me\n' > sweep.txt
mkdir -p sweepdir
printf 'x\n' > sweepdir/x.txt
git clean -nd
git clean -fdx
git log --oneline 'topic~1..topic'
git log --oneline -- nest
git rev-list --count '^topic~1' topic
git log --oneline nosuchrev 2>/dev/null || true   # the error path, quietly
git log --graph --oneline
git log --graph -p -1
# Every date mode, and the decorations, over the same walk.
for mode in default raw iso iso-strict short unix rfc relative local \
            iso-local 'format:%Y-%m-%d %H:%M:%S %z'; do
  git log --date="$mode" --format='%ad|%cd|%ai|%aI|%as|%at|%ar' > /dev/null
done
# Every way of asking what is listed, and what a tree holds.
for flags in -c -m -d -o -t -s --directory '-o --exclude-standard' \
             '-o -i --exclude-standard' '-c -i --exclude-standard' \
             '-cdmo --exclude-standard' '-o --directory --exclude-standard' \
             '-d -s -t'; do
  git ls-files $flags > /dev/null
done
git ls-files -i 2>/dev/null || true          # the error path, quietly
git ls-files -o -i --directory --exclude-standard > /dev/null
git status --ignored --short > /dev/null
git status --ignored --short -uall > /dev/null
git check-ignore -v -n nest nest/deeper/file.txt sweepdir/x.txt || true
git rev-parse --all > /dev/null
git rev-parse --branches --tags --remotes > /dev/null
git rev-list --parents HEAD > /dev/null
git log -3 --format='%h%x09%s' > /dev/null
for stat in --stat=40 --stat=16 --stat=200,50,1 --stat-graph-width=4 \
            --stat-name-width=12 --stat-count=1; do
  git diff "$stat" topic~1 topic > /dev/null
done
git ls-tree HEAD > /dev/null
git ls-tree -r -t HEAD > /dev/null
git ls-tree -l -r HEAD > /dev/null
git ls-tree -d HEAD > /dev/null
git ls-tree HEAD nest > /dev/null
git ls-tree HEAD nest/ > /dev/null
git ls-tree -r -t HEAD nest/deeper > /dev/null
git ls-tree --abbrev=8 HEAD nest > /dev/null
# Which commits a log shows, and who is asked to make one.
git log --oneline --grep=commit
git log --oneline -i --grep=COMMIT
git log --oneline -E --grep='commit|second'
git log --oneline -F --grep='the first'
git log --oneline --invert-grep --grep=commit
git log --oneline --all-match --grep=commit --grep=first
git log --oneline --author=bash-os --committer=bash-os
git log --oneline --no-merges
git log --oneline --merges
git log --oneline --min-parents=0 --max-parents=1
git log --oneline --since=@1 --until=@9999999999
git log --oneline --since='2 years ago'
git rev-list --count --grep=commit HEAD
git log --oneline -S line
git log --oneline -S line -- long.txt
git log --oneline -G 'line [0-9]'
git log --oneline -i --pickaxe-regex -S 'LINE [0-9]+'
git log --oneline -S nothingatall
git format-patch --stdout -2 > mail.mbox
git format-patch --stdout -2 > /dev/null
git format-patch --stdout -1 > /dev/null
git format-patch -o mail -1 > /dev/null
rm -rf mail
# A patch, read back and applied.
git diff HEAD~1 HEAD > round.diff 2>/dev/null || git diff HEAD > round.diff
git apply --stat round.diff > /dev/null || true
git apply --numstat round.diff > /dev/null || true
git apply --summary round.diff > /dev/null || true
git apply --check round.diff 2>/dev/null || true
git apply --check -R round.diff 2>/dev/null || true
git apply -R round.diff 2>/dev/null || true
git apply round.diff 2>/dev/null || true
# Patches that are wrong in the ways a patch from outside can be wrong.
printf 'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,99999 +1,99999 @@\n one\n' > bad1.diff
printf 'diff --git a/x b/x\n@@ -0,0 +1 @@\n' > bad2.diff
printf 'diff --git a/x b/x\nGIT binary patch\nliteral 4\n' > bad3.diff
printf 'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-one\n' > bad4.diff
printf '@@ -1 +1 @@\n one\n' > bad5.diff
printf 'diff --git a/../../escape b/../../escape\n--- a/../../escape\n+++ b/../../escape\n@@ -0,0 +1 @@\n+x\n' > bad6.diff
for bad in bad1.diff bad2.diff bad3.diff bad4.diff bad5.diff bad6.diff; do
  git apply --check "$bad" 2>/dev/null || true
  git apply --stat "$bad" 2>/dev/null || true
  git apply --numstat "$bad" 2>/dev/null || true
  git apply -R --check "$bad" 2>/dev/null || true
done
rm -f bad1.diff bad2.diff bad3.diff bad4.diff bad5.diff bad6.diff
# And mail that is not quite mail.
printf 'From 0 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\n---\n' > bad.mbox
git am bad.mbox 2>/dev/null || git am --abort 2>/dev/null || true
printf 'not mail at all\n' > bad2.mbox
git am bad2.mbox 2>/dev/null || git am --abort 2>/dev/null || true
rm -f bad.mbox bad2.mbox
rm -f round.diff
# And mail read back into a branch of its own.
git checkout -q -b mailed HEAD~1 2>/dev/null && {
  git am mail.mbox 2>/dev/null || git am --abort || true
  git checkout -q topic 2>/dev/null || git checkout -q main
}
rm -f mail.mbox
git grep line || true
git grep -n -i LINE || true
git grep -l line || true
git grep -c -w line || true
git grep -E 'line [0-9]+' || true
git grep -F 'line 7' || true
git grep --cached line || true
git grep line HEAD || true
git grep -v line || true
git shortlog HEAD
git shortlog -sne HEAD
git log | git shortlog -sn
GIT_AUTHOR_NAME='Prefix Author' GIT_AUTHOR_EMAIL='prefix@bash-os.test' \
GIT_AUTHOR_DATE='1750000000 +0000' GIT_COMMITTER_DATE='1750000000 +0000' \
  git commit -q --allow-empty -m 'made with a name given for this command alone'
git log -1 --format='%an <%ae> %ad'
git config --get-regexp '^core' || true
git config --name-only --list
git config --bool core.bare 2>/dev/null || true
git config --add many.things one
git config --add many.things two
git config --get-all many.things
git config --unset-all many.things
git config --remove-section many 2>/dev/null || true
git log --oneline --follow long.txt > /dev/null
git log --follow --stat -1 long.txt > /dev/null
git blame long.txt > /dev/null
git blame -s long.txt > /dev/null
git blame -l -L 1,5 long.txt > /dev/null
git blame nest/deeper/file.txt > /dev/null
git blame nosuchfile 2>/dev/null || true
git count-objects
git count-objects -v
git count-objects -H
# Every object read at once, with every way of asking about the ones nothing
# reaches, and a link that cannot be followed.
git fsck > /dev/null
git fsck --unreachable > /dev/null
git fsck --no-dangling --root --tags > /dev/null
git fsck --connectivity-only --no-reflogs > /dev/null
git fsck --verbose > /dev/null 2>&1
git fsck HEAD > /dev/null
git fsck nosuchthing > /dev/null 2>&1 || true
gone=$(git rev-parse 'HEAD^{tree}')
gone_path=".git/objects/${gone%"${gone#??}"}/${gone#??}"
mv "$gone_path" gone.object 2>/dev/null || true
git fsck > /dev/null 2>&1 || true
git fsck --connectivity-only > /dev/null 2>&1 || true
mv gone.object "$gone_path" 2>/dev/null || true
git diff -R HEAD~1 HEAD > /dev/null
# The same hunks taken word by word, which cuts each side into words and
# compares those.
git diff --word-diff HEAD~1 HEAD > /dev/null
git diff --raw HEAD~1 HEAD > /dev/null
git log --raw -2 > /dev/null
git whatchanged --oneline -2 > /dev/null
git annotate long.txt > /dev/null 2>&1 || true
git blame -c long.txt > /dev/null 2>&1 || true
git diff --word-diff=porcelain HEAD~1 HEAD > /dev/null
git diff --word-diff=none HEAD~1 HEAD > /dev/null
git log -p --word-diff -2 > /dev/null
git show --word-diff > /dev/null
# No context at all, which sets the long tail the two versions share aside
# before comparing what is left.
git diff -U0 HEAD~1 HEAD > /dev/null
git diff -U0 --stat HEAD~1 HEAD > /dev/null
git diff -U0 --word-diff HEAD~1 HEAD > /dev/null
git diff -U0 --word-diff=porcelain HEAD~1 HEAD > /dev/null
git diff --unified=1 HEAD~1 HEAD > /dev/null
git diff -U20 HEAD~1 HEAD > /dev/null
git diff -U0 --inter-hunk-context=2 HEAD~1 HEAD > /dev/null
git diff -U1 --inter-hunk-context 4 HEAD~1 HEAD > /dev/null
git -c diff.interHunkContext=3 diff -U1 HEAD~1 HEAD > /dev/null
git log -p -U0 -2 > /dev/null
# Whitespace overlooked, which compares lines with theirs taken out.
git diff -w HEAD~1 HEAD > /dev/null
git diff -b HEAD~1 HEAD > /dev/null
git diff --ignore-space-at-eol HEAD~1 HEAD > /dev/null
git diff --ignore-cr-at-eol HEAD~1 HEAD > /dev/null
git diff -w --stat HEAD~1 HEAD > /dev/null
git diff -w --numstat HEAD~1 HEAD > /dev/null
git diff -w -U0 HEAD~1 HEAD > /dev/null
git diff -w --word-diff HEAD~1 HEAD > /dev/null
git log -p -w -2 > /dev/null
git blame -w long.txt > /dev/null
# What the working tree holds and no commit does.
printf 'a line nobody committed\n' >> long.txt
git blame long.txt > /dev/null
git blame -s long.txt > /dev/null
git blame -c long.txt > /dev/null
git checkout -- long.txt
# The whole definition, and blank lines overlooked.
git diff -W HEAD~1 HEAD > /dev/null
git diff -W -U0 HEAD~1 HEAD > /dev/null
git diff -W --stat HEAD~1 HEAD > /dev/null
git diff --ignore-blank-lines HEAD~1 HEAD > /dev/null
git diff --ignore-blank-lines -w HEAD~1 HEAD > /dev/null
git diff --ignore-blank-lines --numstat HEAD~1 HEAD > /dev/null
git log -p -W -2 > /dev/null
# What a change brings in that it should not, and what the status says.
git diff --check HEAD~1 HEAD > /dev/null || true
git diff --check > /dev/null || true
git log --check -2 > /dev/null || true
git diff --exit-code HEAD~1 HEAD > /dev/null || true
git diff --quiet HEAD~1 HEAD || true
# A name that has to be quoted, through the forms that quote it.
printf 'awkward\n' > 'a file with spaces.txt'
printf 'awkward\n' > 'caf\303\251.txt'
git add -A
git status --short > /dev/null
git status --porcelain=v2 > /dev/null
git status -z > /dev/null
git ls-files > /dev/null
git ls-files -z > /dev/null
git ls-tree -r HEAD > /dev/null
git commit -q -m 'two awkward names'
git ls-tree -r --name-only HEAD > /dev/null
git diff --name-only HEAD~1 HEAD > /dev/null
git diff -z --name-status HEAD~1 HEAD > /dev/null
git diff HEAD~1 HEAD > /dev/null
git -c core.quotePath=false status --short > /dev/null
git -c core.quotePath=false ls-files > /dev/null
git diff --no-prefix HEAD~1 HEAD > /dev/null
git reflog --format='%gd|%gs' -3
git branch -v
git branch -vv
git branch -a -v
git branch --merged
git branch --no-merged
git branch --contains HEAD~1
git branch --points-at HEAD
git tag -n
git tag -n3
git tag --contains HEAD~1
git tag --points-at HEAD
git tag --merged HEAD
git describe --tags
git describe --tags --long
git describe --always --abbrev=12
git describe --tags --dirty
git describe --tags --match 'v*' 2>/dev/null || true
git describe 2>/dev/null || true                  # the error path, quietly
git log --oneline --decorate
git log --oneline --decorate=full
git log --decorate=full -1
git log --format='%h%d%D' > /dev/null
git log --date=nonsense -1 2>/dev/null || true    # the error path, quietly
git merge-base topic main
git merge-base --is-ancestor main topic || true
git merge-base --independent topic main
git merge-base --octopus topic main

# The three-way merge of one file's three versions.
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > base-file
printf 'ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > our-file
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\nEIGHT\n' > their-file
git merge-file -p our-file base-file their-file
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n' > our-file
printf 'one\ntwo\ndrei\nfour\nFIVE\nsix\nseven\neight\n' > their-file
git merge-file -p -L ours -L base -L theirs our-file base-file their-file || true
git merge-file our-file base-file their-file || true
: > empty-file
git merge-file -p our-file empty-file their-file || true
git reflog > /dev/null

# Merging: a fast-forward, a clean three-way merge, and one that conflicts.
git switch -q -c merge-base-branch main
printf 'shared one\nshared two\nshared three\n' > merged.txt
git add merged.txt
git commit -q -m 'a file to merge'
git switch -q -c merge-left
printf 'LEFT one\nshared two\nshared three\n' > merged.txt
printf 'left only\n' > left.txt
git add .
git commit -q -m 'the left side'
git switch -q merge-base-branch
printf 'shared one\nshared two\nRIGHT three\n' > merged.txt
printf 'right only\n' > right.txt
git add .
git commit -q -m 'the right side'
git merge merge-left -m 'a clean merge'
cat merged.txt
git switch -q -c conflict-left merge-base-branch
printf 'one side\nshared two\nshared three\n' > merged.txt
git add merged.txt
git commit -q -m 'one side of a conflict'
git switch -q merge-base-branch
printf 'the other side\nshared two\nshared three\n' > merged.txt
git add merged.txt
git commit -q -m 'the other side of a conflict'
git merge conflict-left || true
cat merged.txt
git status --short
git status
git status --porcelain=v2
git ls-files -s
git ls-files -u
git ls-files -u -t
git ls-files -t
git commit -m 'refused while unmerged' 2>/dev/null || true
printf 'settled\nshared two\nshared three\n' > merged.txt
git add merged.txt
git commit -m 'the conflict, settled'
git merge conflict-left
git log --oneline -3
git merge --abort 2>/dev/null || true

# Taking one commit onto another branch, and taking one back out.
git switch -q -c picker merge-base-branch
printf 'picked one\npicked two\n' > picked.txt
git add picked.txt
git commit -q -m 'a commit worth picking'
git switch -q merge-base-branch
git cherry-pick picker
git log --oneline -2
git revert --no-edit HEAD
git log --oneline -2
git switch -q -c picker-conflict merge-base-branch
printf 'left\n' > contested.txt
git add contested.txt
git commit -q -m 'left writes contested.txt'
git switch -q merge-base-branch
printf 'right\n' > contested.txt
git add contested.txt
git commit -q -m 'right writes contested.txt'
git cherry-pick picker-conflict 2>/dev/null || true
git status
git status --short
printf 'settled\n' > contested.txt
git add contested.txt
git cherry-pick --continue
git log --oneline -2
git cherry-pick picker-conflict 2>/dev/null || true
git cherry-pick --abort
git status --short

# Putting work aside and taking it back.
git switch -q -c stasher merge-base-branch
printf 'stash one\nstash two\n' > stashed.txt
git add stashed.txt
git commit -q -m 'a file to stash over'
printf 'stash ONE\nstash two\n' > stashed.txt
printf 'newly staged\n' > staged-too.txt
git add staged-too.txt
git stash push -m 'the sanitizer stash'
git status --short
git stash list
git stash show
git stash show -p
git stash pop
git status --short
git stash list
git stash push -m 'to be dropped'
git stash drop
git stash list
git stash push -m 'to be cleared' 2>/dev/null || true
git stash clear
git stash list

# Replaying a branch onto another.
git switch -q -c rebase-base merge-base-branch
printf 'rebase one\n' > r1.txt
git add r1.txt
git commit -q -m 'a commit to replay'
printf 'rebase two\n' > r2.txt
git add r2.txt
git commit -q -m 'another commit to replay'
git switch -q merge-base-branch
printf 'moved on\n' > moved.txt
git add moved.txt
git commit -q -m 'the branch moved on'
git switch -q rebase-base
git rebase merge-base-branch
git log --oneline -4
git status --short
git switch -q -c rebase-clash merge-base-branch
printf 'clashing\n' > clash.txt
git add clash.txt
git commit -q -m 'the clashing commit'
git switch -q merge-base-branch
printf 'also clashing\n' > clash.txt
git add clash.txt
git commit -q -m 'the other clashing commit'
git switch -q rebase-clash
git rebase merge-base-branch 2>/dev/null || true
git status
git status --short
printf 'resolved\n' > clash.txt
git add clash.txt
git rebase --continue
git log --oneline -3
git switch -q -c rebase-abort merge-base-branch
printf 'to abandon\n' > clash.txt
git add clash.txt
git commit -q -m 'a commit to abandon'
git rebase rebase-clash 2>/dev/null || true
git rebase --abort
git status --short

# A rebase that keeps its merges, which builds a todo list of labels and
# merge commands, runs it, stops over a conflict and is taken up again.
git switch -q -c merges-base rebase-base
printf 'one\ntwo\nthree\n' > m.txt
git add m.txt
git commit -q -m 'a file for the merges'
git switch -q -c merges-side
printf 'SIDE\ntwo\nthree\n' > m.txt
git commit -q -am 'the side changes it'
git switch -q merges-base
printf 'TRUNK\ntwo\nthree\n' > m.txt
git commit -q -am 'the trunk changes it'
git merge --no-edit merges-side -m "Merge branch 'merges-side'" 2>/dev/null || true
printf 'settled\ntwo\nthree\n' > m.txt
git add m.txt
git commit -q -m "Merge branch 'merges-side'"
printf 'after\n' > m2.txt
git add m2.txt
git commit -q -m 'after the merge'
git switch -q -c merges-moved merges-base~3
printf 'one\ntwo\nthree\nfour\n' > m.txt
git add m.txt
git commit -q -m 'the base moved under the merges'
git switch -q merges-base
git rebase -r merges-moved 2>/dev/null || true
git status --short
printf 'settled again\ntwo\nthree\nfour\n' > m.txt
git add m.txt
GIT_EDITOR=true git rebase --continue
git log --oneline -4

# A linked worktree, worked in and removed.
git worktree add ../linked-tree
git worktree list
git worktree list --porcelain
cd ../linked-tree
git status --short
printf 'from the linked tree\n' > linked.txt
git add linked.txt
git commit -q -m 'a commit from the linked worktree'
git log --oneline -1
cd "$OLDPWD"
git branch
git worktree remove ../linked-tree
git worktree list
git worktree prune

# Renames: moved, moved and edited, and moved beyond recognition.
git switch -q -c renamer merge-base-branch
printf 'alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\neta\ntheta\n' > renamable.txt
git add renamable.txt
git commit -q -m 'a file to move'
git mv renamable.txt renamed-once.txt
git status --short
git status
git status --porcelain=v2
git diff --cached
git diff --cached --stat
git diff --cached --summary
git diff --cached --name-status
git diff --cached --no-renames --stat
git commit -q -m 'move it'
git mv renamed-once.txt renamed-twice.txt
printf 'alpha\nBETA\ngamma\ndelta\nepsilon\nzeta\neta\nTHETA\n' > renamed-twice.txt
git add renamed-twice.txt
git diff --cached
git diff --cached --summary
git commit -q -m 'move and edit'
git show --stat
git log --name-status -2

# Two repositories: cloning, fetching, pulling and pushing between them.
cd "$HOME"
git clone repo clone-of-repo
cd clone-of-repo
git log --oneline -1
git remote -v
git branch -a
cd "$HOME/repo"
printf 'a change to fetch\n' > fetched.txt
git add fetched.txt
git commit -q -m 'something to fetch'
cd "$HOME/clone-of-repo"
git fetch
git pull
git log --oneline -1
cd "$HOME"
git init -q -b main --bare bare-copy
cd clone-of-repo
git remote add bare ../bare-copy
git push bare
printf 'and another\n' > pushed.txt
git add pushed.txt
git commit -q -m 'something to push'
git push bare
git remote remove bare

# A repository inside a repository: taken in, listed, run in, let go of,
# and taken up again from what was left behind.
cd "$HOME"
git init -q -b main library
printf 'a library\n' > library/lib.txt
git -C library add lib.txt
git -C library commit -q -m 'the library'
cd "$HOME/repo"
git submodule add ../library vendor/library
cat .gitmodules
git status --short
git commit -q -m 'take the library in'
git submodule status
git submodule foreach 'echo "in $name at $sha1"'
git submodule deinit vendor/library
git submodule status
git submodule update --init
git submodule status
cat vendor/library/lib.txt
git submodule deinit --all -f
cd "$HOME/repo"

# Packing by hand, where objects that are nearly the same go in as deltas
# against one another rather than whole: a file changed a line at a time,
# then every object written into a pack and read back out of it.
cd "$HOME/repo"
for round in 1 2 3 4 5 6 7 8 9 10 11 12; do
  printf 'line %s\n' one two three four five six seven eight nine ten > deltas.txt
  printf 'changed %s\n' "$round" >> deltas.txt
  git add deltas.txt
  git commit -q -m "delta round $round"
done
git rev-list --objects HEAD | cut -d' ' -f1 > "$HOME/pack-ids"
git pack-objects "$HOME/by-hand" < "$HOME/pack-ids"
git verify-pack -v "$HOME"/by-hand-*.idx | tail -4
git verify-pack -s "$HOME"/by-hand-*.idx
git index-pack -o "$HOME/by-hand-again.idx" "$HOME"/by-hand-*.pack
git cat-file -p HEAD:deltas.txt | tail -1
cd "$HOME"
# Asking the far end over the protocol, which is pkt-lines all the way.
git ls-remote "$HOME/repo"
git ls-remote --symref --tags "$HOME/repo"
git ls-remote "$HOME/bare-copy"
cd "$HOME/repo"

# Signing, and then reading a signature back: the armour, the key file and
# the allowed-signers list are all blobs walked byte by byte.
if command -v ssh-keygen > /dev/null; then
  ssh-keygen -q -t ed25519 -N '' -C signer@bash-os.test -f "$HOME/sign-key"
  printf 'signer@bash-os.test %s\n' "$(cut -d' ' -f1,2 "$HOME/sign-key.pub")" \
    > "$HOME/allowed"
  signs=(-c gpg.format=ssh -c "user.signingKey=$HOME/sign-key")
  checks=(-c "gpg.ssh.allowedSignersFile=$HOME/allowed")
  git "${signs[@]}" commit -q -S --allow-empty -m 'a signed commit'
  git "${signs[@]}" tag -s -m 'a signed tag' signed-tag
  git "${checks[@]}" verify-commit -v HEAD
  git "${checks[@]}" verify-tag signed-tag
  git "${checks[@]}" log --show-signature -1
  git verify-commit HEAD || true      # nobody vouches for the key here
fi

git fsck 2>/dev/null || true
# Naming a commit after the refs that reach it, which walks the whole
# history from every ref.
git name-rev --name-only HEAD > /dev/null
git name-rev HEAD~1 > /dev/null 2>&1 || true
git name-rev --tags --name-only HEAD > /dev/null 2>&1 || true
git name-rev --all > /dev/null 2>&1 || true
git rev-parse HEAD | git name-rev --annotate-stdin > /dev/null 2>&1 || true
git describe --contains HEAD > /dev/null 2>&1 || true
git describe --all HEAD > /dev/null 2>&1 || true

# What is known about a remote, which asks the far end and reads the refs
# it left here.
git remote > /dev/null
git remote -v > /dev/null
git remote show -n bare > /dev/null 2>&1 || true
git remote show bare > /dev/null 2>&1 || true
git remote prune -n bare > /dev/null 2>&1 || true

# Moving HEAD about, which says where it was and how the branch stands.
git checkout topic
git checkout main
git checkout HEAD~1 2>/dev/null || true
git checkout main
git checkout --detach HEAD~1 2>/dev/null || true
git checkout -
git switch topic
git switch -
git rev-parse '@{-1}' > /dev/null 2>&1 || true

# A bundle, which is the refs and a pack of what they reach in one file.
git bundle create "$HOME/all.bundle" --all > /dev/null 2>&1 || true
git bundle list-heads "$HOME/all.bundle" > /dev/null 2>&1 || true
git bundle verify "$HOME/all.bundle" > /dev/null 2>&1 || true
git bundle create "$HOME/since.bundle" HEAD~1..HEAD > /dev/null 2>&1 || true
git bundle verify "$HOME/since.bundle" > /dev/null 2>&1 || true
git bundle unbundle "$HOME/all.bundle" > /dev/null 2>&1 || true
git bundle verify "$HOME/pack-ids" > /dev/null 2>&1 || true   # not a bundle
git clone -q "$HOME/all.bundle" "$HOME/clone-of-bundle" > /dev/null 2>&1 || true
git clone -q "$HOME/since.bundle" "$HOME/no-clone" > /dev/null 2>&1 || true

# An archive of the tree, which walks every object and writes every byte.
git archive HEAD > /dev/null
git archive --prefix=pre/ HEAD > /dev/null
git archive HEAD nest > /dev/null
git archive -o "$HOME/archive.tar" HEAD
git archive "HEAD^{tree}" > /dev/null
git archive --list > /dev/null
git archive --format=zip HEAD > /dev/null 2>&1 || true

# Bisecting, which walks the history counting what each commit reaches.
git bisect start > /dev/null 2>&1 || true
git bisect bad > /dev/null 2>&1 || true
git bisect good HEAD~2 > /dev/null 2>&1 || true
git bisect skip > /dev/null 2>&1 || true
git bisect log > /dev/null 2>&1 || true
git bisect terms > /dev/null 2>&1 || true
git bisect reset > /dev/null 2>&1 || true
git bisect start HEAD HEAD~3 > /dev/null 2>&1 || true
git bisect run test -f long.txt > /dev/null 2>&1 || true
git bisect reset > /dev/null 2>&1 || true

# Notes: a tree of text beside the commits, read on every log line.
git notes add -m 'a note on the tip' > /dev/null 2>&1 || true
git notes append -m 'a second line' > /dev/null 2>&1 || true
git notes add -m 'on an older one' HEAD~1 > /dev/null 2>&1 || true
git notes list > /dev/null
git notes show > /dev/null
git log -3 > /dev/null
git log -3 --format='%h %N' > /dev/null
git log -3 --no-notes > /dev/null
git notes --ref reviews add -m 'looked at it' > /dev/null 2>&1 || true
git log -1 --notes=reviews > /dev/null
git notes remove HEAD~1 > /dev/null 2>&1 || true
git notes prune > /dev/null

# The housekeeping, which reads every reflog and then every object.
git gc --auto > /dev/null
git gc --no-prune > /dev/null
git gc --prune=now > /dev/null
git gc > /dev/null
git log --oneline > /dev/null
git fsck 2>/dev/null || true
# Putting the store into one pack and taking the loose copies away, which
# walks every object twice: once to choose what goes in, once to delta it.
git repack > /dev/null
git repack -d > /dev/null
git repack -a -d > /dev/null
git repack -a -d > /dev/null
git count-objects -v > /dev/null
git log --oneline > /dev/null
git cat-file --batch-all-objects --batch-check > /dev/null
# Last, because it takes objects away: the same walk fsck does, and then
# every loose object nothing reaches.
git prune -n > /dev/null
git prune -n -v > /dev/null
git prune --expire=2.weeks.ago -n > /dev/null
git prune HEAD > /dev/null 2>&1 || true
git prune -v > /dev/null
git fsck 2>/dev/null || true
SCENARIO

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
LD_PRELOAD=$("$CC" -print-file-name=libasan.so) \
GIT_SO="$d/git.so" \
GIT_CONFIG_NOSYSTEM=1 HOME="$d" LC_ALL=C TZ=UTC \
GIT_AUTHOR_NAME='Sanitize Author' GIT_AUTHOR_EMAIL=author@bash-os.test \
GIT_AUTHOR_DATE='1750000000 +0000' \
GIT_COMMITTER_NAME='Sanitize Committer' GIT_COMMITTER_EMAIL=committer@bash-os.test \
GIT_COMMITTER_DATE='1750000100 +0000' \
  "$target" --noprofile --norc -c "cd '$repo' && . '$d/scenario.sh'" > "$d/out" 2> "$d/err" \
  || { tail -5 "$d/out"; cat "$d/err" >&2; echo 'git-sanitize: the scenario stopped early'; exit 1; }

if grep -qE 'runtime error|AddressSanitizer|LeakSanitizer' "$d/err"; then
  cat "$d/err"
  echo 'git-sanitize: sanitizer reported a problem'
  exit 1
fi
# The scenario itself must have run clean: git says nothing on stderr here
# except what the commands are meant to say.
if grep -qE '^(fatal|usage):' "$d/err"; then
  cat "$d/err"
  echo 'git-sanitize: a command failed'
  exit 1
fi
lines=$(wc -l < "$d/out")
echo "git-sanitize: instrumented git ran the scenario clean ($lines lines of output)"
