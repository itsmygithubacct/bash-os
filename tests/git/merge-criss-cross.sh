#!/usr/bin/env bash
# Two branches that have merged each other have two merge bases, and
# neither on its own is what the next merge should be held against: git
# merges the bases into one of its own making and holds the merge against
# that. This is that shape, twice over — once settling and once not.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit merge merge-base checkout log status rev-parse
set -e

git init -q -b main .
printf 'one\ntwo\nthree\nfour\nfive\n' > f.txt
git add f.txt
git commit -q -m 'the start'

git checkout -q -b topic
printf 'one\nTWO\nthree\nfour\nfive\n' > f.txt
git commit -q -am 'topic changes the second line'
theirs=$(git rev-parse HEAD)

git checkout -q main
printf 'one\ntwo\nthree\nFOUR\nfive\n' > f.txt
git commit -q -am 'main changes the fourth line'
ours=$(git rev-parse HEAD)

# Each merges what the other had then, which is what leaves two bases.
git merge -q --no-edit "$theirs"
git checkout -q topic
git merge -q --no-edit "$ours"
git checkout -q main
printf 'MAIN\ntwo\nthree\nFOUR\nfive\n' > f.txt
git commit -q -am 'main goes on'
git checkout -q topic
printf 'one\nTWO\nthree\nfour\nFIVE\n' > f.txt
git commit -q -am 'topic goes on'
git checkout -q main

echo '=== two bases ==='
git merge-base --all main topic | sort
git log --format='%s' --all | sort

echo '=== and a merge held against both of them ==='
git merge --no-edit topic
cat f.txt
git log --format='%s' -1
git log --format='%T' -1
git status --short

echo '=== the same shape, with the two sides over one line ==='
git checkout -q -b second-base main
printf 'alpha\nbeta\ngamma\n' > g.txt
git add g.txt
git commit -q -m 'a second file'
git checkout -q -b other second-base
printf 'alpha\nBETA-theirs\ngamma\n' > g.txt
git commit -q -am 'other changes the middle'
mine=$(git rev-parse second-base)
theirs=$(git rev-parse HEAD)
git checkout -q second-base
printf 'alpha\nBETA-ours\ngamma\n' > g.txt
git commit -q -am 'second-base changes the middle too'
ours=$(git rev-parse HEAD)
git merge --no-edit "$theirs" || echo "merge said no: $?"
printf 'alpha\nBETA-settled\ngamma\n' > g.txt
git add g.txt
git commit -q -m 'settled here'
git checkout -q other
git merge --no-edit "$ours" || echo "merge said no: $?"
printf 'alpha\nBETA-settled-differently\ngamma\n' > g.txt
git add g.txt
git commit -q -m 'settled there'
git checkout -q second-base

echo '=== bases again ==='
git merge-base --all second-base other | sort

echo '=== and what a merge over the made-up base says ==='
git merge --no-edit other || echo "merge said no: $?"
cat g.txt
git status --short
git merge --abort
git status --short
cat g.txt
