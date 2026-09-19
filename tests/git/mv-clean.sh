#!/usr/bin/env bash
# Moving tracked paths and removing untracked ones. Renames are compared
# with --no-renames on both sides: this build does not detect renames yet,
# and says so rather than pretending. Run through tests/git-parity.py,
# never on its own.
# requires: init add commit mv clean status ls-files
set -e

git init -q -b main .
printf 'x\n' > a.txt
mkdir sub
printf 'y\n' > sub/b.txt
git add .
git commit -q -m 'first commit'

echo '=== mv a file ==='
git mv a.txt renamed.txt
git ls-files
git status --short --no-renames
test ! -e a.txt && echo 'the old name is gone'

echo '=== mv into a directory ==='
git mv -v renamed.txt sub/
git ls-files
git commit -q -m 'second commit'
git status --short --no-renames

echo '=== mv refuses what it cannot do ==='
git mv nope.txt other.txt || echo "bad source: $?"
git mv sub/b.txt sub/renamed.txt || echo "destination exists: $?"
git mv -k nope.txt other.txt && echo 'with -k a bad source is skipped'
git ls-files

echo '=== mv --dry-run changes nothing ==='
git mv -n sub/b.txt moved.txt
git ls-files
test -e sub/b.txt && echo 'the file stayed where it was'

echo '=== mv a directory ==='
git mv sub other
git ls-files
git status --short --no-renames
git commit -q -m 'third commit'

echo '=== clean ==='
printf '*.log\n' > .gitignore
git add .gitignore
git commit -q -m 'ignore logs'
printf 'junk\n' > junk.txt
mkdir dirt
printf 'j\n' > dirt/j.txt
printf 'ignored\n' > ig.log
git clean || echo "refused without -f: $?"
git clean -n
git clean -nd
git clean -ndx
git clean -ndX
git status --short
echo '=== clean for real ==='
git clean -f
git status --short
git clean -fd -- dirt
git status --short
git clean -fdxq
git status --short
git ls-files

echo '=== restoring everything under . ==='
printf 'edited\n' >> other/b.txt
git add other/b.txt
git status --short
git restore --staged .
git status --short
git restore .
git status --short
