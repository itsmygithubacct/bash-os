#!/usr/bin/env bash
# Which commits changed how often a string appears (-S), and which added
# or took away a line a pattern matches (-G) — over a history with a
# branch and a merge, since a merge answers to neither.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit branch checkout merge log
set -e

git init -q -b main .
printf 'alpha\nbeta\n' > f.txt
printf 'one\n' > other.txt
git add f.txt other.txt
git commit -q -m 'first: alpha beta'
printf 'alpha\nbeta\ngamma\n' > f.txt
git commit -q -am 'second: add gamma'
git checkout -q -b side
printf 'alpha\nbeta\ngamma\ndelta\n' > f.txt
git commit -q -am 'side: add delta'
git checkout -q main
printf 'alpha\nBETA\ngamma\n' > f.txt
git commit -q -am 'main: shout beta'
git merge --no-edit side || {
    printf 'alpha\nBETA\ngamma\ndelta\n' > f.txt
    git add f.txt
    git commit -q -m 'settled the merge'
}
printf 'alpha\nBETA\ngamma\n' > f.txt
printf 'one\ndelta\n' > other.txt
git commit -q -am 'drop delta from one file and add it to another'

echo '=== how often a string appears ==='
git log --oneline -S delta
git log --oneline -S gamma
git log --oneline -S BETA
git log --oneline -S alpha
git log --oneline -Sdelta
git log --oneline -S delta -- f.txt
git log --oneline -S delta -- other.txt
git log --oneline -S delta -- nosuch
git log --oneline -i -S BeTa
git log --oneline --pickaxe-regex -S 'del.a'
git log --oneline -i --pickaxe-regex -S 'be.a'
git log --oneline -S nothingatall

echo '=== a line added or taken away ==='
git log --oneline -G '^delta'
git log --oneline -G beta
git log --oneline -G BeTa
git log --oneline -i -G BeTa
git log --oneline -Gdelta
git log --oneline -G delta -- other.txt
git log --oneline -G nothingatall

echo '=== and with the rest of the filters ==='
git log --oneline -S delta --no-merges
git log --oneline -S delta -1
git log --oneline -S delta --stat
git log --oneline -S delta --grep=drop
git log --oneline -S delta --author=Parity

echo '=== a pattern is read the extended way ==='
git log --oneline -G 'alpha|beta'
git log --oneline -G 'l[a-z]+a'
git log --oneline --pickaxe-regex -S 'l[a-z]+a'
git log --oneline -i -G 'ALPHA|BETA'
