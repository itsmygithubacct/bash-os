#!/usr/bin/env bash
# The ways a pull can end: a fast-forward, a merge, a replay, and a
# refusal when only a fast-forward will do. The repositories live under
# HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit pull fetch clone log status config merge
# requires: rebase rev-parse
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
cd ..
git clone -q far near
root=$PWD

echo '=== a pull that only has to catch up ==='
cd far
printf 'two\n' >> a.txt
git commit -q -am 'the second commit'
cd ../near
git pull --ff-only 2>&1 | sed "s|$root|ROOT|"
git log --oneline

echo '=== a pull that has to replay what is here ==='
printf 'mine\n' > mine.txt
git add mine.txt
git commit -q -m 'a commit of my own'
cd ../far
printf 'three\n' >> a.txt
git commit -q -am 'the third commit'
cd ../near
git pull --rebase 2>&1 | sed "s|$root|ROOT|"
git log --oneline
git status --short

echo '=== a pull that will not fast-forward, when that is all that is allowed ==='
printf 'mine again\n' > mine.txt
git add mine.txt
git commit -q -m 'another commit of my own'
cd ../far
printf 'four\n' >> a.txt
git commit -q -am 'the fourth commit'
cd ../near
# git's advice here goes to stderr, which the harness drops "hint:" from
# but which this scenario folds into its own output, so it is dropped
# here instead.
git pull --ff-only > "$HOME/pull.log" 2>&1 || echo "status: $?"
sed "/^hint:/d; s|$root|ROOT|" "$HOME/pull.log"
git log --oneline -1

echo '=== and the configuration can ask for the replay ==='
git config pull.rebase true
git pull 2>&1 | sed "s|$root|ROOT|"
git log --oneline
