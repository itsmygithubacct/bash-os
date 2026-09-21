#!/usr/bin/env bash
# Bisecting: halving a history to find the commit that first went wrong,
# with the verdicts kept as refs and the transcript that can replay them.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit bisect checkout branch merge rev-list log grep
set -e

# git 2.55 puts the two terms in quotes where 2.47 does not — "waiting for
# both 'good' and 'bad' commits" against "waiting for both good and bad
# commits". The quotes are taken off both sides rather than pinning one
# git; nothing else in this scenario quotes those words.
terms () { sed -e "s/'good'/good/g" -e "s/'bad'/bad/g" \
               -e "s/'broken'/broken/g" -e "s/'works'/works/g"; }

git init -q -b main .
for i in 1 2 3 4 5 6 7 8; do
  printf 'line %s\n' "$i" >> f.txt
  git add f.txt
  git commit -q -m "commit $i"
done

echo '=== one end at a time ==='
git bisect start | terms
git bisect bad | terms
git bisect good HEAD~7 | terms
git log --oneline -1
git status --porcelain=v2 --branch | head -2

echo '=== and on to the end ==='
git bisect good | terms
git bisect bad | terms
git bisect good | terms
git bisect log | terms
git bisect reset
git log --oneline -1

echo '=== both ends at once, and one skipped ==='
git bisect start HEAD HEAD~7 | terms
git bisect skip | terms
git bisect log | terms
git for-each-ref refs/bisect --format='%(refname)'
git bisect reset

echo '=== terms of its own ==='
git bisect start --term-new=broken --term-old=works | terms
git bisect broken | terms
git bisect works HEAD~7 | terms
git bisect terms | terms
git bisect terms --term-good | terms
git bisect terms --term-bad | terms
git bisect log | terms
git bisect reset

echo '=== what it says when it cannot work ==='
git bisect good 2>&1 | terms || echo "said no: $?"
git bisect log || echo "said no: $?"
git bisect start | terms
git bisect good HEAD~3 | terms
# git 2.55 puts the two words in quotes here where 2.47 does not; the
# quotes are taken out of both sides rather than pinning one git.
git bisect bad HEAD~5 2>&1 | sed "s/'//g"
if git bisect bad HEAD~5 > /dev/null 2>&1; then echo 'said: 0'; else echo "said: $?"; fi
git bisect reset

echo '=== a transcript replayed ==='
git bisect start HEAD HEAD~7 > /dev/null
git bisect good | terms
git bisect bad | terms
git bisect log > ../replay.txt
git bisect reset > /dev/null
git bisect replay ../replay.txt | terms
git bisect log | terms
git bisect reset
rm -f ../replay.txt

echo '=== run, with a command deciding ==='
git bisect start HEAD HEAD~7 > /dev/null
git bisect run grep -q -v 'line 6' f.txt | terms
git bisect log | tail -3 | terms
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
git bisect start HEAD "$(git rev-list --max-parents=0 HEAD)" | terms
git bisect good | terms
git bisect bad | terms
git bisect log | terms
git bisect reset
git log --oneline -1
git status --porcelain=v2 --branch | head -2
