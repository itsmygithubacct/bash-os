#!/usr/bin/env bash
# A rebase that keeps the merges: the todo list it writes, with a label for
# every branch it will bring back in, and the reset and merge commands that
# put them together again. What is looked at here is the shape of that list
# and what running it leaves behind — including a merge that conflicts, is
# settled by hand, and taken up again.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit merge rebase log status rev-parse checkout branch config
set -e

# git's own spelling of a todo line changed between versions — 2.47 writes
# "pick <id> <subject>" and 2.55 writes "pick <id> # <subject>" — so the
# scripts that copy a list out level that one difference as they write,
# which is also the shape the harness compares the copies in. Everything
# else about the lists is compared exactly. Nothing but the shell itself
# is used: these run with no PATH at all.
level='  case $line in "pick "*" # "*|"#    pick "*" # "*)'
level="$level"' line="${line%% # *} ${line#* # }";; esac'
printf '%s\n' '#!/bin/sh' 'while IFS= read -r line; do' "$level" \
  '  printf "%s\n" "$line"' 'done < "$1" > shown' > show-todo
chmod 755 show-todo

git init -q -b main .
# The dates here are pinned, and so in the past. A repository this busy is
# enough for git to decide it is time to tidy up, and a tidy-up takes
# every reflog entry older than ninety days with it — which is all of
# them — leaving the two sides with different histories of themselves. So
# this repository is told to leave that alone.
git config gc.auto 0
git config gc.reflogExpire never
git config gc.reflogExpireUnreachable never
git config maintenance.auto false
commit() { printf '%s\n' "$2" > "$1"; git add "$1"; git commit -q -m "$3"; }

commit b1.txt one 'base one'
commit b2.txt two 'base two'
git checkout -q -b side
commit s1.txt 'side one' 'side one'
commit s2.txt 'side two' 'side two'
git checkout -q main
commit m1.txt 'main one' 'main one'
git merge -q --no-edit side -m "Merge branch 'side'"
commit a.txt after 'after the merge'
git branch newbase main~4
git checkout -q newbase
commit g.txt moved 'the base moved'
git checkout -q main

echo '=== the list it writes ==='
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i -r newbase
cat shown

echo '=== and what it left ==='
git log --format='%s'
git log --format='%s' HEAD~1^2
git log --format='%p %s' -1
git status --short

echo '=== the same rebase again, which has nothing to move ==='
git rebase -r newbase
git log --format='%s' -1

echo '=== a branch inside a branch ==='
git checkout -q -b outer newbase
commit o1.txt 'outer one' 'outer one'
git checkout -q -b inner
commit i1.txt 'inner one' 'inner one'
git checkout -q outer
commit o2.txt 'outer two' 'outer two'
git merge -q --no-edit inner -m "Merge branch 'inner' into outer"
git checkout -q -b trunk newbase
commit t1.txt 'trunk one' 'trunk one'
git merge -q --no-edit outer -m "Merge branch 'outer'"
git branch farther newbase
git checkout -q farther
commit f1.txt 'farther along' 'farther along'
git checkout -q trunk
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i -r farther
cat shown
git log --format='%s'
git log --format='%s' HEAD^2
git log --format='%p %s' -1

echo '=== a branch that grew below the upstream ==='
git checkout -q -b cousin newbase
commit c1.txt 'cousin one' 'cousin one'
git checkout -q -b cousin-main newbase
commit c2.txt 'cousin main' 'cousin main'
git merge -q --no-edit cousin -m "Merge branch 'cousin'"
git branch cousin-base newbase
git checkout -q cousin-base
commit c3.txt 'cousin base' 'cousin base'
git checkout -q cousin-main
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i -r cousin-base || echo "rebase said no: $?"
cat shown
git log --format='%s'

echo '=== and the same, told to move the cousins too ==='
git reset -q --hard cousin-main@{1} 2>/dev/null || true
git log --format='%s' -1
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i --rebase-merges=rebase-cousins cousin-base || echo "rebase said no: $?"
cat shown
git log --format='%s'
git status --short

echo '=== a branch whose own base is further back ==='
git checkout -q -b deep newbase
commit d1.txt 'deep one' 'deep one'
commit d2.txt 'deep two' 'deep two'
git checkout -q -b deep-side deep~1
commit d3.txt 'deep side' 'deep side'
git checkout -q deep
git merge -q --no-edit deep-side -m "Merge branch 'deep-side'"
commit d4.txt 'after it' 'after the deep merge'
git branch deep-base deep~2
git checkout -q deep-base
commit d5.txt 'moved' 'the deep base moved'
git checkout -q deep
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i -r deep-base
cat shown
git log --format='%s'
git log --format='%s' HEAD~1^2
git log --format='%p %s' -1
git status --short

echo '=== a merge that does not settle ==='
printf '%s\n' '#!/bin/sh' 'while IFS= read -r line; do' "$level" \
  '  printf "%s\n" "$line"' 'done < "$1" > editor-saw' > keep-message
chmod 755 keep-message
export GIT_EDITOR=./keep-message

git checkout -q -b tangle newbase
printf 'one\ntwo\nthree\n' > t.txt
git add t.txt
git commit -q -m 'a file both sides will change'
git checkout -q -b tangle-side
printf 'SIDE\ntwo\nthree\n' > t.txt
git commit -q -am 'the side changes the first line'
git checkout -q tangle
printf 'TANGLE\ntwo\nthree\n' > t.txt
git commit -q -am 'the trunk changes the first line'
git merge --no-edit tangle-side -m "Merge branch 'tangle-side'" || echo "merge said no: $?"
printf 'settled\ntwo\nthree\n' > t.txt
git add t.txt
git commit -q -m "Merge branch 'tangle-side'"
printf 'x\n' > t2.txt
git add t2.txt
git commit -q -m 'after the tangle'
git branch tangle-base tangle~3
git checkout -q tangle-base
printf 'one\ntwo\nthree\nfour\n' > t.txt
git add t.txt
git commit -q -m 'the base moved under it'
git checkout -q tangle

git rebase -r tangle-base || echo "rebase said no: $?"
git status --short
cat t.txt
git log --format='%s' -1

echo '=== settled by hand, and taken up again ==='
printf 'settled again\ntwo\nthree\nfour\n' > t.txt
git add t.txt
git rebase --continue
git log --format='%s'
git log --format='%p %s' -1
git status --short
cat editor-saw

echo '=== and one that is called off ==='
git reset -q --hard tangle@{1}
git log --format='%s' -1
git rebase -r tangle-base || echo "rebase said no: $?"
git rebase --abort
git status --short
git log --format='%s' -1
git log --format='%s' HEAD~1^2

echo '=== and a plain rebase, which flattens the merges away ==='
git checkout -q -b flat newbase
commit p1.txt 'flat one' 'flat one'
git checkout -q -b flat-side
commit p2.txt 'flat side' 'flat side'
git checkout -q flat
commit p3.txt 'flat two' 'flat two'
git merge -q --no-edit flat-side -m "Merge branch 'flat-side'"
commit p4.txt 'after it' 'after the flat merge'
git branch flat-base flat~3
git checkout -q flat-base
commit p5.txt 'moved' 'the flat base moved'
git checkout -q flat
git rebase flat-base
git log --format='%s'
git status --short
