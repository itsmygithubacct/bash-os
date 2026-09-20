#!/usr/bin/env bash
# What a clone can be asked for: a branch by name, no working tree, and
# a remote called something other than origin. The repositories live
# under HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit branch switch clone status config log
# requires: for-each-ref rev-parse ls-files
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git switch -q -c side
printf 'from the side\n' > s.txt
git add s.txt
git commit -q -m 'a commit on the side'
git switch -q main
cd ..
root=$PWD

echo '=== a branch by name ==='
git clone -q -b side far named
cd named
git rev-parse --abbrev-ref HEAD
git log --oneline -1
git config --get branch.side.merge
ls s.txt
cd ..

echo '=== no working tree ==='
git clone -q --no-checkout far empty
cd empty
git rev-parse --abbrev-ref HEAD
git status --short
git ls-files
git log --oneline -1
cd ..

echo '=== a remote called something else ==='
git clone -q --origin upstream far renamed
cd renamed
git remote
git config --get remote.upstream.url | sed "s|$root|ROOT|"
git config --get remote.upstream.fetch
git config --get branch.main.remote
git for-each-ref --format='%(refname)' refs/remotes/
cd ..

echo '=== and a branch that is not there ==='
git clone -q -b nowhere far nothing 2>&1 || echo "status: $?"
