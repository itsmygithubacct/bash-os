#!/usr/bin/env bash
# A repository that holds another one. The index entry for a submodule is a
# commit id, not a file, and status, diff and add all have to know it: what
# the repository over there has checked out is what the entry is held
# against, and nothing inside it belongs to this one.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit status diff update-index rev-parse ls-files log
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'top\n' > t.txt
git add t.txt
git commit -q -m 'the first commit'

# The submodule is made by hand: `git submodule add` is not part of this
# build, and by hand is something both implementations can do the same way.
git init -q -b main lib
printf 'library\n' > lib/l.txt
git -C lib add l.txt
git -C lib commit -q -m 'the library'
first=$(git -C lib rev-parse HEAD)
git update-index --add --cacheinfo "160000,$first,lib"
printf '[submodule "lib"]\n\tpath = lib\n\turl = ./lib\n' > .gitmodules
git add .gitmodules
git commit -q -m 'the submodule'

echo '=== as it stands ==='
git ls-files -s
git status --short
git status
git diff
git log --format='%T' -1

echo '=== the submodule moves on ==='
printf 'library\nmore\n' > lib/l.txt
git -C lib add l.txt
git -C lib commit -q -m 'the library moved'
git status --short
git status
git diff
git diff --stat

echo '=== and its own tree is dirty ==='
printf 'and more\n' >> lib/l.txt
printf 'untracked\n' > lib/u.txt
git status --short
git status

echo '=== only untracked files in it ==='
git -C lib checkout -q -- l.txt
git status --short

echo '=== staging the commit it has now ==='
rm lib/u.txt
git add lib
git status --short
git diff --cached
git commit -q -m 'the submodule at its new commit'
git ls-files -s
git log --format='%T' -1

echo '=== nothing checked out there at all ==='
rm -rf lib/.git lib/l.txt
git status --short
git status
git diff
git ls-files -s

echo '=== and gone entirely ==='
rmdir lib
git status --short
git diff
