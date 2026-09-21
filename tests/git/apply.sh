#!/usr/bin/env bash
# Applying a patch: what --check says before anything is written, what
# --stat, --numstat and --summary say about it, and what applying it
# leaves behind — in the working tree, in the index, or in both.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit diff apply status reset checkout mv
set -e

git init -q -b main .
mkdir -p sub
printf 'one\ntwo\nthree\nfour\nfive\n' > f.txt
printf 'old\n' > gone.txt
printf 'a\nb\nc\nd\ne\nf\ng\nh\n' > many.txt
printf 'no newline' > ragged.txt
printf 'deep\n' > sub/deep.txt
printf 'x\n' > move.txt
git add -A
git commit -q -m 'the first commit'

# A patch that changes, adds, removes, renames and shifts a mode.
printf 'one\nTWO\nthree\nfour\nfive\nsix\n' > f.txt
rm gone.txt
printf 'fresh\n' > new.txt
printf 'A\nb\nc\nd\ne\nf\ng\nH\n' > many.txt
printf 'no newline at all' > ragged.txt
printf 'deeper\n' > sub/deep.txt
git mv move.txt moved.txt
chmod +x sub/deep.txt
git add -A
git diff --cached > all.diff
git reset -q --hard HEAD
rm -f new.txt

echo '=== what the patch says it does ==='
cat all.diff
git apply --stat all.diff
git apply --numstat all.diff
git apply --summary all.diff
git apply --check all.diff
echo "check: $?"

echo '=== and what it does ==='
git apply all.diff
git status --short
cat f.txt
cat many.txt
cat ragged.txt
echo
cat sub/deep.txt

echo '=== and back again ==='
rm -f moved.txt
git checkout -q -- .
git apply -R all.diff || echo "reverse said no: $?"
git status --short

echo '=== a hunk that has moved down the file ==='
git reset -q --hard HEAD
rm -f new.txt moved.txt
printf 'a\nb\nc\nd\nE\nf\ng\nh\n' > many.txt
git diff -- many.txt > mid.diff
git checkout -q -- many.txt
printf 'zero\na\nb\nc\nd\ne\nf\ng\nh\n' > many.txt
git apply mid.diff
echo "shifted: $?"
cat many.txt
git checkout -q -- many.txt

echo '=== one that does not fit, and one that is not a patch ==='
printf 'CHANGED\ntwo\nthree\nfour\nfive\n' > f.txt
git apply --check all.diff || echo "said no: $?"
git apply all.diff || echo "said no: $?"
git checkout -q -- f.txt
printf 'not a patch at all\n' > junk.diff
git apply junk.diff || echo "said no: $?"

echo '=== into the index, and into the index alone ==='
git reset -q --hard HEAD
rm -f new.txt moved.txt
git apply --index all.diff
git status --short
git reset -q --hard HEAD
rm -f new.txt moved.txt
git apply --cached all.diff
git status --short
git reset -q --hard HEAD
rm -f new.txt moved.txt

echo '=== and one that tries to climb out of the repository ==='
printf 'diff --git a/../escape.txt b/../escape.txt\nindex 1234567..89abcde 100644\n--- a/../escape.txt\n+++ b/../escape.txt\n@@ -1 +1 @@\n-one\n+two\n' > escape.diff
git apply escape.diff || echo "said no: $?"
git apply --check escape.diff || echo "said no: $?"
printf 'diff --git a/.git/config b/.git/config\nindex 1234567..89abcde 100644\n--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-x\n+y\n' > dotgit.diff
git apply dotgit.diff || echo "said no: $?"
rm -f escape.diff dotgit.diff

echo '=== and from a pipe ==='
cat all.diff | git apply --check
echo "piped: $?"
rm -f all.diff mid.diff junk.diff
