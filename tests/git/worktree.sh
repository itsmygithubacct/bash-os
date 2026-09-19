#!/usr/bin/env bash
# Linked worktrees: adding one, listing them, working in one, and removing
# it. Paths are rewritten to REPO so the two runs can be compared from
# different directories, and runs of spaces in the listing are squeezed to
# one: git 2.47 pads the path column two spaces wide where 2.55 pads it one,
# and the porcelain listing below is compared exactly anyway. Run through tests/git-parity.py, never on its own.
# requires: init add commit worktree branch status log switch rev-parse
set -e

git init -q -b main .
printf 'base\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
root=$PWD

echo '=== one worktree to start with ==='
git worktree list | sed "s|$root|REPO|;s/  */ /g"

echo '=== adding one ==='
git worktree add ../side
git worktree list | sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|;s/  */ /g"
git branch
cat ../side/.git | sed "s|$root|REPO|"

echo '=== working in it ==='
cd ../side
git status --short
git rev-parse --abbrev-ref HEAD
printf 'from the side worktree\n' > s.txt
git add s.txt
git commit -q -m 'a commit from the side worktree'
git log --oneline
cd "$root"
git log --oneline side
git log --oneline
git branch

echo '=== the porcelain listing ==='
git worktree list --porcelain | sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|"

echo '=== a worktree on a new branch ==='
git worktree add -b feature ../feature main
git worktree list | sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|;s/  */ /g"
git branch

echo '=== removing one ==='
git worktree remove ../feature
git worktree list | sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|;s/  */ /g"
git branch
test ! -e ../feature && echo 'the directory is gone'

echo '=== a branch checked out twice is refused ==='
# The refusal names the worktree by its absolute path, on stderr, so both
# streams are rewritten before they are compared.
git worktree add ../again side > "$HOME/out" 2> "$HOME/err" || echo "refused: $?"
sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|" "$HOME/out" "$HOME/err"
git worktree list | sed "s|$root|REPO|;s|$(cd .. && pwd)|PARENT|;s/  */ /g"
