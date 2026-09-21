#!/usr/bin/env bash
# A rebase carrying the other branches along: the `update-ref` lines git
# writes into the todo list for every branch standing on a commit being
# replayed, and the refs moving to where those commits end up — at the
# end, not as they go, which is what makes a stopped rebase still know
# about them.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit branch checkout rebase log status config
set -e

# git's own spelling of a todo line changed between versions — 2.47 writes
# "pick <id> <subject>" and 2.55 writes "pick <id> # <subject>" — so the
# script that copies the list out levels that one difference as it writes,
# in the shell alone, since it runs with no PATH.
level='  case $line in "pick "*" # "*)'
level="$level"' line="${line%% # *} ${line#* # }";; esac'
printf '%s\n' '#!/bin/sh' 'while IFS= read -r line; do' "$level" \
  '  printf "%s\n" "$line"' 'done < "$1" > shown' > show-todo
chmod 755 show-todo

git init -q -b main .
for i in 1 2 3 4; do
  printf 'file %d\n' "$i" > "f$i.txt"
  git add "f$i.txt"
  git commit -q -m "commit $i"
done
git branch part-one HEAD~2
git branch part-two HEAD~1
git branch newbase main~3
git checkout -q newbase
printf 'moved\n' > moved.txt
git add moved.txt
git commit -q -m 'the base moved'
git checkout -q main

echo '=== the list it writes ==='
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i --update-refs newbase
cat shown

echo '=== and what moved ==='
git log --format='%s'
for branch in part-one part-two main; do
  printf '%-9s %s\n' "$branch" "$(git log --format='%s' -1 "$branch")"
done
git reflog part-one | head -1
git status --short

echo '=== the same, asked for by configuration ==='
git reset -q --hard main@{1}
git branch -f part-one main~2
git branch -f part-two main~1
git config rebase.updateRefs true
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i newbase
cat shown
for branch in part-one part-two; do
  printf '%-9s %s\n' "$branch" "$(git log --format='%s' -1 "$branch")"
done

echo '=== and a rebase that keeps its merges, carrying them too ==='
git reset -q --hard main@{1}
git branch -f part-one main~2
git branch -f part-two main~1
git checkout -q -b topic main~2
printf 'on the topic\n' > topic.txt
git add topic.txt
git commit -q -m 'a commit on the topic'
git checkout -q main
git merge -q --no-edit topic -m "Merge branch 'topic'"
GIT_SEQUENCE_EDITOR=./show-todo git rebase -i -r --update-refs newbase
cat shown
git log --format='%s' -1
git log --format='%s' HEAD^2
for branch in part-one part-two topic main; do
  printf '%-9s %s\n' "$branch" "$(git log --format='%s' -1 "$branch")"
done

echo '=== and one that stops on the way ==='
git config --unset rebase.updateRefs
git reset -q --hard main@{1}
git branch -f part-one main~2
git branch -f part-two main~1
# Nothing but the shell here either: the list is read whole and written
# back with a stop put in after the first branch is reached.
printf '%s\n' '#!/bin/sh' 'kept=""' 'while IFS= read -r line; do' \
  '  kept="$kept$line' '"' \
  '  case $line in "update-ref refs/heads/part-one") kept="${kept}break' '"' \
  ';; esac' 'done < "$1"' 'printf "%s" "$kept" > "$1"' > break-after
chmod 755 break-after
GIT_SEQUENCE_EDITOR=./break-after git rebase -i --update-refs newbase
git log --format='%s' -1
for branch in part-one part-two; do
  printf '%-9s %s\n' "$branch" "$(git log --format='%s' -1 "$branch")"
done
git rebase --continue
for branch in part-one part-two main; do
  printf '%-9s %s\n' "$branch" "$(git log --format='%s' -1 "$branch")"
done
git status --short
