#!/usr/bin/env bash
# Bisecting: halving a history to find the commit that first went wrong,
# with the verdicts kept as refs and the transcript that can replay them.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit bisect checkout branch merge rev-list log grep
set -e

git init -q -b main .
for i in 1 2 3 4 5 6 7 8; do
  printf 'line %s\n' "$i" >> f.txt
  git add f.txt
  git commit -q -m "commit $i"
done

echo '=== one end at a time ==='
git bisect start
git bisect bad
git bisect good HEAD~7
git log --oneline -1
git status --porcelain=v2 --branch | head -2

echo '=== and on to the end ==='
git bisect good
git bisect bad
git bisect good
git bisect log
git bisect reset
git log --oneline -1

echo '=== both ends at once, and one skipped ==='
git bisect start HEAD HEAD~7
git bisect skip
git bisect log
git for-each-ref refs/bisect --format='%(refname)'
git bisect reset

echo '=== terms of its own ==='
git bisect start --term-new=broken --term-old=works
git bisect broken
git bisect works HEAD~7
git bisect terms
git bisect terms --term-good
git bisect terms --term-bad
git bisect log
git bisect reset

echo '=== what it says when it cannot work ==='
git bisect good || echo "said no: $?"
git bisect log || echo "said no: $?"
git bisect start
git bisect good HEAD~3
git bisect bad HEAD~5 || echo "said no: $?"
git bisect reset

echo '=== a transcript replayed ==='
git bisect start HEAD HEAD~7 > /dev/null
git bisect good
git bisect bad
git bisect log > ../replay.txt
git bisect reset > /dev/null
git bisect replay ../replay.txt
git bisect log
git bisect reset
rm -f ../replay.txt

echo '=== run, with a command deciding ==='
git bisect start HEAD HEAD~7 > /dev/null
git bisect run grep -q -v 'line 6' f.txt
git bisect log | tail -3
git bisect reset

echo '=== over a history that forks and joins ==='
git checkout -q -b side HEAD~4
printf 'a side line\n' >> g.txt
git add g.txt
git commit -q -m 'a side commit'
git checkout -q main
git merge --no-ff -m 'merge the side in' side > /dev/null
printf 'line 9\n' >> f.txt
git add f.txt
git commit -q -m 'commit 9'
git bisect start HEAD "$(git rev-list --max-parents=0 HEAD)"
git bisect good
git bisect bad
git bisect log
git bisect reset
git log --oneline -1
git status --porcelain=v2 --branch | head -2
