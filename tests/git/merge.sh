#!/usr/bin/env bash
# Merging: already up to date, fast-forward, a real merge, and a merge that
# refuses. Conflicts have their own scenario. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit switch branch merge log status diff rev-parse
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
printf 'base\n' > a.txt
git add a.txt
git commit -q -m 'the common commit'

echo '=== already up to date ==='
git branch topic
git merge topic
echo "status: $?"

echo '=== fast-forward ==='
git switch -q topic
printf 'topic\n' > t.txt
git add t.txt
git commit -q -m 'topic commit'
git switch -q main
git merge topic
git log --oneline
git status --short
git rev-parse --abbrev-ref HEAD

echo '=== fast-forward refused by --no-ff, then taken ==='
git switch -q -c ahead main
printf 'ahead\n' > ahead.txt
git add ahead.txt
git commit -q -m 'ahead commit'
git switch -q main
git merge --no-ff ahead -m 'merge ahead with no fast-forward'
git log --oneline
git log -1 --format='%s%n%P'

echo '=== a real merge, both sides ahead ==='
git switch -q -c side main~1
printf 'side\n' > s.txt
git add s.txt
git commit -q -m 'side commit'
git switch -q main
printf 'main moved\n' > m.txt
git add m.txt
git commit -q -m 'main commit'
git merge side
git log --oneline
git log -1 --format='%s%n%P'
git status --short
git ls-files

echo '=== --ff-only on diverged branches ==='
git switch -q -c other main~1
printf 'other\n' > o.txt
git add o.txt
git commit -q -m 'other commit'
git switch -q main
git merge --ff-only other || echo "refused: $?"
git log --oneline -1

echo '=== merging a commit id, not a branch ==='
id=$(git rev-parse other)
git merge "$id"
git log -1 --format='%s'

echo '=== the same file changed on both sides, cleanly ==='
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > shared.txt
git add shared.txt
git commit -q -m 'shared file'
git switch -q -c edit main
printf 'ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > shared.txt
git add shared.txt
git commit -q -m 'edit the first line'
git switch -q main
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\nEIGHT\n' > shared.txt
git add shared.txt
git commit -q -m 'edit the last line'
git merge edit
cat shared.txt
git status --short
git log --oneline -1

echo '=== merge refuses over an untracked file ==='
git switch -q -c adder main
printf 'from the branch\n' > new.txt
git add new.txt
git commit -q -m 'add new.txt'
git switch -q main
printf 'in the way\n' > new.txt
git merge adder || echo "refused: $?"
cat new.txt
git status --short
