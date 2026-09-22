#!/usr/bin/env bash
# What `git remote show` says about a remote: where it is, what branch its
# HEAD is on, which of its branches are tracked here, which of ours follow
# one of its, and where a push would go. And what `git remote prune` takes
# away once a branch over there is gone.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit branch remote fetch config update-ref rev-parse log
set -e

# The far end, beside this repository rather than inside it.
mkdir ../upstream
(
  cd ../upstream
  git init -q -b main .
  printf 'one\n' > f.txt
  git add f.txt
  git commit -q -m 'the first commit'
  git branch topic
  git branch going-away
)

git init -q -b main .
git remote add origin ../upstream
git fetch -q origin
# git 2.55 writes refs/remotes/origin/HEAD on a fetch where 2.47 does not;
# the file is taken away here so that both gits leave the same refs behind.
# It is a symbolic ref, and `update-ref -d` would follow it to the branch it
# names and delete that instead.
rm -f .git/refs/remotes/origin/HEAD
git config branch.main.remote origin
git config branch.main.merge refs/heads/main
git update-ref refs/heads/main refs/remotes/origin/main
git checkout -q main

echo '=== the remotes themselves ==='
git remote
git remote -v
git remote get-url origin

echo '=== and what is known about one ==='
git remote show origin
git remote show -n origin

echo '=== with one of ours following one of theirs ==='
git update-ref refs/heads/topic refs/remotes/origin/topic
git config branch.topic.remote origin
git config branch.topic.merge refs/heads/topic
git remote show origin

echo '=== once ours has moved on ==='
git checkout -q topic
printf 'two\n' > f.txt
git commit -q -am 'a commit only here'
git checkout -q main
git remote show origin | tail -4

echo '=== and once theirs has ==='
(
  cd ../upstream
  git branch -D going-away
)
git remote show origin | sed -n '5,9p'
git remote prune -n origin
git remote prune origin
git remote show origin | sed -n '5,8p'

# A name no remote has is taken for a URL by git and tried as one, so
# what comes back is the far end's complaint rather than anything about
# remotes; it is left out of this comparison.

rm -rf ../upstream
