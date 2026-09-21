#!/usr/bin/env bash
# What prune takes away: the loose objects nothing reaches, the temporary
# files a write left behind, and the fanout directories that end up empty —
# and what it leaves, which is everything a ref, the index or a reflog still
# reaches. The listing is in git's object-table order, so it is sorted.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit reset hash-object commit-tree prune fsck rev-parse
set -e

git init -q -b main .
printf 'one\n' > f.txt
git add f.txt
git commit -q -m 'the first commit'
printf 'two\n' > f.txt
git commit -q -am 'the second commit'

echo '=== a reflog still reaches what a reset moved off ==='
git reset -q --hard HEAD~1
git prune -n | sort
git count-objects

echo '=== what is staged is held too ==='
printf 'staged\n' > s.txt
git add s.txt
git prune -n | sort

echo '=== objects nothing points at ==='
printf 'loose one\n' | git hash-object -w --stdin
printf 'loose two\n' | git hash-object -w --stdin
loose=$(git commit-tree -m 'a commit nothing points at' "$(git rev-parse HEAD^{tree})")
git prune -n | sort
echo '--- unless that commit is named'
git prune -n "$loose" | sort
echo '--- and not while they are newer than the cutoff'
git prune --expire=2.weeks.ago -n | sort

echo '=== taking them away ==='
mkdir -p .git/objects/ab
: > .git/objects/tmp_obj_unfinished
git prune -v | sort
ls .git/objects | sort
git count-objects -v
git fsck | sort
git log --oneline
git status --porcelain=v2 --branch
