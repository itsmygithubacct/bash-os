#!/usr/bin/env bash
# What status says about the branch a branch follows: up to date, ahead,
# behind, diverged, and an upstream that is configured but not there any
# more — in the long format, the short one with -b, and porcelain v2. The
# repositories live under HOME, which the harness does not compare.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit clone fetch status reset branch checkout config
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > one.txt
git add one.txt
git commit -q -m 'the first commit'
cd ..
git clone -q far near
cd near

report() {
  git status
  git status -sb
  git status --porcelain=v2 --branch
}

echo '=== in step with what it follows ==='
report

echo '=== a commit ahead ==='
printf 'mine\n' > mine.txt
git add mine.txt
git commit -q -m 'a commit of my own'
report

echo '=== and two behind as well ==='
cd ../far
printf 'two\n' > two.txt
git add two.txt
git commit -q -m 'the second commit'
printf 'three\n' > three.txt
git add three.txt
git commit -q -m 'the third commit'
cd ../near
git fetch -q
report

echo '=== behind alone ==='
git reset -q --hard origin/main~2
report

echo '=== an upstream that is no longer there ==='
git update-ref -d refs/remotes/origin/main
report

echo '=== a branch that follows nothing ==='
git checkout -q -b alone
report

echo '=== and one that follows another branch here ==='
git config branch.alone.remote .
git config branch.alone.merge refs/heads/main
report
