#!/usr/bin/env bash
# What a push can be asked for: a refspec, a tag, a forced update, a
# deletion, and a run that says what it would do without doing it. The
# repositories live under HOME, which the harness does not compare. Run
# through tests/git-parity.py, never on its own.
# requires: init add commit branch tag push remote log for-each-ref
# requires: rev-parse config switch
set -e

cd "$HOME"
git init -q -b main --bare dest.git
git init -q -b main src
cd src
printf 'one\n' > a.txt
git add a.txt
git commit -q -m 'the first commit'
git tag v1
git switch -q -c side
printf 'from the side\n' > s.txt
git add s.txt
git commit -q -m 'a commit on the side'
git switch -q main

echo '=== a branch by name, and a tag with it ==='
git push ../dest.git main --tags 2>&1
git -C ../dest.git for-each-ref --format='%(refname)'

echo '=== a refspec that renames on the way ==='
git push ../dest.git side:refs/heads/elsewhere 2>&1
git -C ../dest.git for-each-ref --format='%(refname)'

echo '=== saying what it would do, and not doing it ==='
printf 'two\n' >> a.txt
git commit -q -am 'the second commit'
git push --dry-run ../dest.git main 2>&1
git -C ../dest.git log --oneline main

echo '=== and then doing it ==='
git push ../dest.git main 2>&1
git -C ../dest.git log --oneline main

echo '=== a push that would lose commits, refused and then forced ==='
git reset -q --hard HEAD~1
printf 'another line entirely\n' > a.txt
git commit -q -am 'a different second commit'
# git's advice after a refusal goes to stderr, which the scenario folds
# into its output; the harness drops "hint:" from stderr but not from
# what a scenario prints, so it is dropped here.
git push ../dest.git main > "$HOME/push.log" 2>&1 || echo "status: $?"
sed '/^hint:/d' "$HOME/push.log"
git push --force ../dest.git main 2>&1
git -C ../dest.git log --oneline main

echo '=== unmaking refs, both ways round ==='
git push ../dest.git :refs/tags/v1 2>&1
git push --delete ../dest.git refs/heads/elsewhere 2>&1
git -C ../dest.git for-each-ref --format='%(refname)'

echo '=== nothing left to say ==='
git push ../dest.git main 2>&1

echo '=== and a push that makes the branch follow where it went ==='
git remote add origin ../dest.git
git switch -q -c followed
printf 'a branch that will follow\n' > f.txt
git add f.txt
git commit -q -m 'a commit to follow'
git push -u origin followed 2>&1
git config --get branch.followed.remote
git config --get branch.followed.merge
git for-each-ref --format='%(refname)' refs/remotes/
