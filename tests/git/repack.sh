#!/usr/bin/env bash
# Putting the store into one pack and taking away what that makes
# redundant: the packs it replaces and the loose copies it holds. The size
# of a pack is not compared — this build's delta search settles for a
# slightly larger one — but what the pack holds is, object for object.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit repack count-objects cat-file fsck log clone grep
set -e

git init -q -b main .
for i in 1 2 3 4 5; do
  printf 'line %s\n' "$i" >> f.txt
  git add f.txt
  git commit -q -m "commit $i"
done
printf 'nothing points at this\n' | git hash-object -w --stdin

echo '=== before ==='
git count-objects

echo '=== one pack of what is reachable ==='
git repack -a -d
git count-objects -v | grep -v '^size'
git cat-file --batch-all-objects --batch-check
git log --oneline
git cat-file -p HEAD:f.txt
git fsck | sort

echo '=== loose again, beside the pack ==='
printf 'line 6\n' >> f.txt
git add f.txt
git commit -q -m 'after the pack'
git count-objects -v | grep -v '^size'

echo '=== an incremental pass takes the new ones ==='
git repack
git count-objects -v | grep -v '^size'
echo '--- and -d takes the loose copies away'
git repack -d
git count-objects -v | grep -v '^size'
echo '--- with nothing left to do'
git repack
git repack -a -d
git count-objects -v | grep -v '^size'

echo '=== everything still reads ==='
git log --oneline
git cat-file --batch-all-objects --batch-check
git cat-file -p HEAD:f.txt
git fsck | sort
git status --porcelain=v2 --branch

echo '=== and it can be cloned from ==='
git clone -q . ./copy
git -C ./copy log --oneline
git -C ./copy cat-file -p HEAD:f.txt
# A local clone here asks the far end for what is reachable, where git
# copies the object store whole, unreachable objects and all; what each
# clone has nothing pointing at is its own business.
git -C ./copy fsck | grep -v '^dangling ' | sort
rm -rf copy
