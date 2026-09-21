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
# requires: rev-list ls-files
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

echo '=== taking one in with add ==='
git init -q -b main second
printf 'the second library\n' > second/s.txt
git -C second add s.txt
git -C second commit -q -m 'the second library'
git -c protocol.file.allow=always submodule add ./second vendor/second 2>&1 | tidy
cat .gitmodules
git status --short
git ls-files -s
git config --local --get submodule.vendor/second.url | tidy
git config --local --get submodule.vendor/second.active
git commit -q -m 'the second submodule'

echo '=== what the repository holds, which is not the submodule ==='
# A gitlink names a commit of another repository: this one does not have
# it, and does not list it among its own objects.
git rev-list --objects HEAD | sort

echo '=== running something in each of them ==='
git submodule foreach 'echo "name=$name path=$sm_path sha=$sha1 here=${toplevel##*/}"' | tidy
git submodule foreach --quiet 'echo "quiet $name"'
git submodule foreach 'exit 3' || echo "status $?"

echo '=== and letting one go with deinit ==='
git submodule status | tidy
git submodule deinit vendor/second
git submodule status | tidy
git status --short
git config --local --get submodule.vendor/second.url || echo '(nothing configured)'
ls vendor/second | wc -l

echo '=== which a deinit will not do over local changes ==='
git -c protocol.file.allow=always submodule update --init vendor/second 2>&1 | tidy
printf 'changed\n' >> vendor/second/s.txt
git submodule deinit vendor/second || echo "status $?"
git submodule deinit -f vendor/second
git submodule status | tidy

echo '=== and a path that names no submodule ==='
git submodule deinit nowhere || echo "status $?"

# The upstreams are not part of what is compared: they are repositories of
# their own, and two implementations write their insides differently.
rm -rf upstream second
git status --short
