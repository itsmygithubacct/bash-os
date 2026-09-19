#!/usr/bin/env bash
# What the far end has, asked for over the protocol rather than read off
# the disk: ls-remote starts upload-pack and speaks protocol v2 to it, so
# this compares both ends of a conversation at once. The repositories live
# under HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit tag branch ls-remote remote push
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git branch other
git tag light
git tag -a heavy -m 'an annotated tag'
cd ..

echo '=== every ref it has ==='
git ls-remote far

echo '=== branches only, then tags only ==='
git ls-remote --heads far
git ls-remote --tags far

echo '=== and what HEAD points at ==='
git ls-remote --symref far

echo '=== a bare repository answers the same way ==='
git init -q -b main --bare bare.git
cd far
git remote add copy ../bare.git
git push -q copy main
cd ..
git ls-remote bare.git

echo '=== a name from the configuration stands for its path ==='
git init -q -b main here
cd here
git remote add origin ../far
git ls-remote
git ls-remote origin
cd ..

echo '=== and a path that is not a repository is refused ==='
mkdir -p empty
git ls-remote empty || echo "status: $?"
