#!/usr/bin/env bash
# `git submodule`: what it says about a submodule, registering one, and
# fetching it into place from a path on this machine. The upstream sits in
# an ignored directory inside the tree so nothing outside it is touched,
# and the paths in the output are put back to '.' so that two runs in two
# directories can be held against each other. Fetching over a path is
# something git refuses unless the command line says otherwise, which is
# why -c stands where it does; this build has no such rule and does not
# mind being told.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit status submodule update-index rev-parse config
set -e

here=$PWD
tidy() { sed "s|$here|.|g"; }

git init -q -b main .
printf 'top\n' > t.txt
printf 'upstream/\n' > .gitignore
git add t.txt .gitignore
git commit -q -m 'the first commit'

# What the submodule will be fetched from, kept where nothing tracks it.
git init -q -b main upstream
printf 'library\n' > upstream/l.txt
git -C upstream add l.txt
git -C upstream commit -q -m 'the library'
first=$(git -C upstream rev-parse HEAD)

mkdir lib
git update-index --add --cacheinfo "160000,$first,lib"
printf '[submodule "lib"]\n\tpath = lib\n\turl = ./upstream\n' > .gitmodules
git add .gitmodules
git commit -q -m 'the submodule'
rmdir lib

echo '=== before anything is fetched ==='
git submodule status
git status --short

echo '=== registering it ==='
git submodule init 2>&1 | tidy
git config --get submodule.lib.url | tidy
git config --get submodule.lib.active

echo '=== and fetching it ==='
git -c protocol.file.allow=always submodule update 2>&1 | tidy
cat lib/.git
cat lib/l.txt
git submodule status
git status --short

echo '=== when it has moved on ==='
printf 'library\nmore\n' > upstream/l.txt
git -C upstream add l.txt
git -C upstream commit -q -m 'the library moved'
second=$(git -C upstream rev-parse HEAD)
git -C lib fetch -q origin
git -C lib checkout -q "$second"
git submodule status
git submodule status --cached
git status --short

echo '=== and when the index is told about it ==='
git add lib
git commit -q -m 'the submodule at its new commit'
git submodule status
git status --short
git ls-files -s

echo '=== update with nothing to do ==='
git -c protocol.file.allow=always submodule update 2>&1 | tidy

echo '=== and update --init from nothing ==='
rm -rf lib .git/modules
git config --unset submodule.lib.url
git config --unset submodule.lib.active
git submodule status
git -c protocol.file.allow=always submodule update --init 2>&1 | tidy
cat lib/l.txt
git submodule status
git status --short

# The upstream is not part of what is compared: it is a repository of its
# own, and two implementations write its insides differently.
rm -rf upstream
git status --short
