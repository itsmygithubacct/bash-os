#!/usr/bin/env bash
# Ranges and pathspecs: which commits a range names, and which of them
# touched a path. Run through tests/git-parity.py, never on its own.
# requires: init add commit log rev-list branch switch
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
echo '=== a repository with no commits ==='
git log || echo "no commits yet: $?"

for i in 1 2 3; do
  printf 'line %d\n' "$i" >> a.txt
  git add a.txt
  git commit -q -m "commit $i"
done
printf 'other\n' > b.txt
git add b.txt
git commit -q -m 'add b'

echo '=== the whole history ==='
git log --oneline
git rev-list --count HEAD

echo '=== ranges ==='
git log --oneline 'HEAD~2..HEAD'
git log --oneline 'HEAD~3..'
git log --oneline '..HEAD'
git log --oneline '^HEAD~2' HEAD
git rev-list --count 'HEAD~2..HEAD'
git rev-list 'HEAD~1..HEAD'
git rev-list --count '^HEAD~1' HEAD

echo '=== ranges across branches ==='
git switch -q -c topic
printf 'topic\n' > t.txt
git add t.txt
git commit -q -m 'topic commit'
git switch -q main
printf 'more\n' >> b.txt
git add b.txt
git commit -q -m 'main moves on'
git log --oneline 'main..topic'
git log --oneline 'topic..main'
git rev-list --count 'main..topic'
git rev-list --count 'topic..main'

echo '=== pathspecs ==='
git log --oneline -- a.txt
git log --oneline -- b.txt
git log --oneline -- t.txt
git log --oneline -1 -- a.txt
git log --stat -1 -- a.txt
git log -p -1 -- b.txt
git log --oneline 'main..topic' -- t.txt
git log --name-status -2 -- b.txt

echo '=== the graph column ==='
git log --graph --oneline
git log --graph -2
git log --graph --stat -1
git log --graph -p -1 -- b.txt

echo '=== names that do not resolve ==='
git log --oneline 'HEAD~9..HEAD' || echo "bad range: $?"
git log --oneline nosuchrev || echo "bad revision: $?"
git rev-list nosuchrev || echo "bad rev-list: $?"
git rev-list --count '^nosuchrev' HEAD || echo "bad exclusion: $?"
