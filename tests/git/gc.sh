#!/usr/bin/env bash
# The housekeeping: everything reachable into one pack, the loose copies
# away with it, and what is unreachable and old enough taken away. How the
# store is laid out afterwards is each implementation's own business — git
# keeps recent unreachable objects in a cruft pack where this build leaves
# them loose — so what is compared is what the repository still holds and
# still says.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit gc hash-object cat-file fsck log worktree
set -e

git init -q -b main .
for i in 1 2 3; do
  printf 'line %s\n' "$i" >> f.txt
  git add f.txt
  git commit -q -m "commit $i"
done
printf 'nothing points at this\n' | git hash-object -w --stdin

echo '=== --auto has nothing to do in a repository this small ==='
git gc --auto
git count-objects

echo '=== the housekeeping itself ==='
git gc
git log --oneline
git cat-file -p HEAD:f.txt
git cat-file --batch-all-objects --batch-check | sort
git fsck | sort
git status --porcelain=v2 --branch

echo '=== and what it keeps, it keeps ==='
git gc
git log --oneline
git cat-file --batch-all-objects --batch-check | sort

echo '=== until the cutoff says otherwise ==='
git gc --prune=now
git cat-file --batch-all-objects --batch-check | sort
git fsck | sort

echo '=== with --no-prune, what is unreachable stays ==='
printf 'nor this\n' | git hash-object -w --stdin
git gc --no-prune
git fsck | sort
git cat-file --batch-all-objects --batch-check | sort

echo '=== a worktree it has not lost sight of long enough to forget ==='
git worktree add ../side > /dev/null 2>&1
git gc --prune=now
git worktree list | wc -l
rm -rf ../side
git gc --prune=now
git worktree list | wc -l
git log --oneline
git fsck | sort
