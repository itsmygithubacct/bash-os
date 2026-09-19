#!/usr/bin/env bash
# Two repositories on one machine: cloning, fetching, pulling and pushing
# between them. Paths are rewritten so the two runs can be compared from
# different directories. Run through tests/git-parity.py, never on its own.
# requires: init add commit clone fetch pull push remote branch log status
# requires-feature: diff-patch diff-stat
set -e

# The repositories live under HOME, not in the directory the harness
# compares: a nested .git would be compared file by file, and git's own
# init leaves sample hooks in it that this build does not.
cd "$HOME"
git init -q -b main origin-repo
cd origin-repo
printf 'one\ntwo\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git switch -q -c other
printf 'from the other branch\n' > o.txt
git add o.txt
git commit -q -m 'the other commit'
git switch -q main
cd ..
root=$PWD

echo '=== cloning ==='
git clone origin-repo copy 2>&1 | sed "s|$root|ROOT|"
cd copy
git log --oneline
git branch
git branch -a
git remote
git remote -v | sed "s|$root|ROOT|"
git config --get remote.origin.fetch
git config --get branch.main.remote
git config --get branch.main.merge
git status --short
cat a.txt
git for-each-ref --format='%(refname) %(objecttype)'

echo '=== the origin moves on ==='
cd ../origin-repo
printf 'three\n' >> a.txt
git commit -q -am 'the origin moves on'
cd ../copy
git fetch 2>&1 | sed "s|$root|ROOT|"
git log --oneline --all
git log --oneline
git pull 2>&1 | sed "s|$root|ROOT|"
git log --oneline
cat a.txt

echo '=== a second fetch has nothing to do ==='
git fetch 2>&1 | sed "s|$root|ROOT|"
echo "status: $?"

echo '=== pushing to a bare repository ==='
cd ..
git init -q -b main --bare bare-repo
cd copy
git remote add bare ../bare-repo
git remote
git push bare main 2>&1
git push bare main 2>&1
printf 'four\n' >> a.txt
git commit -q -am 'a commit to push'
git push bare main 2>&1
cd ../bare-repo
git log --oneline
git for-each-ref --format='%(refname)'
cd ..

echo '=== cloning the bare one ==='
git clone bare-repo second 2>&1 | sed "s|$root|ROOT|"
cd second
git log --oneline
git branch -a
git status --short
cat a.txt
cd ..

echo '=== remotes can be managed ==='
cd copy
git remote add spare ../bare-repo
git remote -v | sed "s|$root|ROOT|"
git remote get-url spare | sed "s|$root|ROOT|"
git remote set-url spare ../origin-repo
git remote get-url spare
git remote remove spare
git remote
git remote remove nothing || echo "no such remote: $?"
