#!/usr/bin/env bash
# A bundle: the refs and the objects behind them in one file, to be carried
# somewhere there is no network. The file itself is not compared — the pack
# inside it is this build's own — but everything said about it is, and so is
# what a repository holds after taking one in.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit tag bundle update-ref cat-file log fsck rev-parse
# requires: clone config for-each-ref symbolic-ref status
set -e

git init -q -b main .
for i in 1 2 3; do
  printf 'line %s\n' "$i" >> f.txt
  git add f.txt
  git commit -q -m "commit $i"
done
git tag v1
git branch side

echo '=== everything in one ==='
git bundle create ../all.bundle --all
git bundle list-heads ../all.bundle
git bundle verify ../all.bundle

echo '=== only what is asked for ==='
git bundle create ../main.bundle main
git bundle list-heads ../main.bundle
git bundle create ../two.bundle main v1
git bundle list-heads ../two.bundle

echo '=== and only what is new ==='
git bundle create ../since.bundle HEAD~1..HEAD
git bundle list-heads ../since.bundle
git bundle verify ../since.bundle

echo '=== taking one in ==='
mkdir ../dest
(
  cd ../dest
  git init -q -b main .
  git bundle unbundle ../all.bundle
  # The objects are in; the refs are the caller's to make, as git leaves
  # them.
  git update-ref refs/heads/main "$(git bundle list-heads ../all.bundle | head -1 | cut -d' ' -f1)"
  git log --oneline
  git cat-file -p HEAD:f.txt
  git fsck | sort
)

echo '=== cloned from ==='
# git's init says which branch name it chose when nothing tells it, and a
# clone from a bundle starts with an init; naming it here keeps both quiet.
git config --global init.defaultBranch main
git clone -q ../all.bundle ../clone-of-all
git -C ../clone-of-all for-each-ref --format='%(refname) %(objectname)'
git -C ../clone-of-all symbolic-ref HEAD
git -C ../clone-of-all log --oneline
git -C ../clone-of-all status --porcelain=v2 --branch
git -C ../clone-of-all fsck | sort
git -C ../clone-of-all config --get remote.origin.fetch
git clone -q -b side ../all.bundle ../clone-of-side
git -C ../clone-of-side symbolic-ref HEAD
git clone -q --bare ../all.bundle ../bare-of-all
git -C ../bare-of-all for-each-ref --format='%(refname) %(objectname)'
git -C ../bare-of-all symbolic-ref HEAD
# One that takes something for granted cannot start a clone.
git clone -q ../since.bundle ../clone-of-since || echo "said no: $?"
rm -rf ../clone-of-all ../clone-of-side ../bare-of-all ../clone-of-since

echo '=== what it will not do ==='
git bundle create ../empty.bundle || echo "said no: $?"
git bundle verify ../nosuch.bundle || echo "said no: $?"
git bundle list-heads f.txt || echo "said no: $?"

rm -rf ../dest ../all.bundle ../main.bundle ../two.bundle ../since.bundle
