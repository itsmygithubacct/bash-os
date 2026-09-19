#!/usr/bin/env bash
# A bare clone, and a push that names a path rather than a remote. A bare
# repository is where branches live, not a copy of somewhere else's, so
# git writes them as branches and keeps no tracking refs. The repositories
# live under HOME, which the harness does not compare: git's init leaves
# sample hooks that this build does not write. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit branch tag clone push for-each-ref config
# requires: rev-parse symbolic-ref log
set -e

cd "$HOME"
git init -q -b main src
cd src
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git branch other
git tag -a v1 -m 'an annotated tag'
cd ..

echo '=== cloning it bare ==='
git clone --bare src bare.git 2>&1 | sed "s|$HOME|HOME|"
cd bare.git
git for-each-ref --format='%(refname) %(objecttype)'
git rev-parse --is-bare-repository
git symbolic-ref HEAD
git config --get core.bare
git config --get remote.origin.url | sed "s|$HOME|HOME|"
git config --get remote.origin.fetch || echo "no fetch refspec: $?"
git log --oneline
cd ..

echo '=== pushing to it by path, not by name ==='
cd src
printf 'two\n' >> a.txt
git commit -q -am 'the second commit'
git push ../bare.git main 2>&1 | sed "s|$HOME|HOME|"
git push ../bare.git main 2>&1 | sed "s|$HOME|HOME|"
echo '--- and nothing here is tracking it:'
git for-each-ref --format='%(refname)'
cd ../bare.git
git log --oneline
cd ..
