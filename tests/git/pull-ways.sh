#!/usr/bin/env bash
# The ways a pull can end: a fast-forward, a merge, a replay, and a
# refusal when only a fast-forward will do. The repositories live under
# HOME, which the harness does not compare. Run through
# tests/git-parity.py, never on its own.
# requires: init add commit pull fetch clone log status config merge remote
# requires: rebase rev-parse
set -e

cd "$HOME"
git init -q -b main far
cd far
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
cd ..
git clone -q far near
root=$PWD

echo '=== a pull that only has to catch up ==='
cd far
printf 'two\n' >> a.txt
git commit -q -am 'the second commit'
cd ../near
git pull --ff-only 2>&1 | sed "s|$root|ROOT|"
git log --oneline

echo '=== a pull that has to replay what is here ==='
printf 'mine\n' > mine.txt
git add mine.txt
git commit -q -m 'a commit of my own'
cd ../far
printf 'three\n' >> a.txt
git commit -q -am 'the third commit'
cd ../near
git pull --rebase 2>&1 | sed "s|$root|ROOT|"
git log --oneline
git status --short

echo '=== a pull that will not fast-forward, when that is all that is allowed ==='
printf 'mine again\n' > mine.txt
git add mine.txt
git commit -q -m 'another commit of my own'
cd ../far
printf 'four\n' >> a.txt
git commit -q -am 'the fourth commit'
cd ../near
# git's advice here goes to stderr, which the harness drops "hint:" from
# but which this scenario folds into its own output, so it is dropped
# here instead.
git pull --ff-only > "$HOME/pull.log" 2>&1 || echo "status: $?"
sed "/^hint:/d; s|$root|ROOT|" "$HOME/pull.log"
git log --oneline -1

echo '=== and the configuration can ask for the replay ==='
git config pull.rebase true
git pull 2>&1 | sed "s|$root|ROOT|"
git log --oneline

echo '=== a pull of a path, which is not a remote ==='
git config --unset pull.rebase
cd "$root/far"
printf 'again\n' > again.txt
git add again.txt
git commit -q -m 'the far end moves on again'
git checkout -q -b sideline
printf 'sideways\n' > sideways.txt
git add sideways.txt
git commit -q -m 'a commit on the sideline'
git checkout -q main
cd "$root/near"
git pull --no-rebase ../far 2>&1 | sed "s|$root|ROOT|"
git log --format='%s' -1
sed "s|$root|ROOT|" .git/FETCH_HEAD

echo '=== and of a branch of it, which has to be merged ==='
printf 'mine\n' > mine.txt
git add mine.txt
git commit -q -m 'a commit of my own'
git pull --no-rebase ../far sideline 2>&1 | sed "s|$root|ROOT|"
git log --format='%s' -3
git log --format='%p' -1
git status --short

echo '=== a pull it will not guess about ==='
cd "$root/far"
printf 'far again\n' > far-again.txt
git add far-again.txt
git commit -q -m 'the far end goes its own way'
cd "$root/near"
printf 'near again\n' > near-again.txt
git add near-again.txt
git commit -q -m 'and this end goes its own'
# The advice is a dozen hint: lines the harness drops from stderr, and
# folding stderr into this output would keep them, so they are dropped
# here as well; the refusal itself is what is compared.
git pull > "$HOME/divergent.log" 2>&1 || echo "status: $?"
sed "/^hint:/d; s|$root|ROOT|" "$HOME/divergent.log"
git log --format='%s' -1

echo '=== until it is told which way ==='
# The merge message a pull writes names where it pulled from, and the two
# sides of the comparison stand in different directories, so the remote is
# pointed at a relative path first.
git remote set-url origin ../far
git pull --no-rebase 2>&1 | sed "s|$root|ROOT|"
git log --format='%s' -2
git status --short
