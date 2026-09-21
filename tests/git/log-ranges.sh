#!/usr/bin/env bash
# Ranges and pathspecs: which commits a range names, and which of them
# touched a path. Run through tests/git-parity.py, never on its own.
# requires: init add commit log rev-list branch switch
# requires-feature: diff-patch diff-stat
set -e

git init -q -b main .
echo '=== a repository with no commits ==='
git log || echo "no commits yet: $?"

for i in 1 2 3; do
  printf 'line %d\n' "$i" >> a.txt
  git add a.txt
  git commit -q -m "commit $i"
done
printf 'other\n' > b.txt
git add b.txt
git commit -q -m 'add b'

echo '=== the whole history ==='
git log --oneline
git rev-list --count HEAD

echo '=== ranges ==='
git log --oneline 'HEAD~2..HEAD'
git log --oneline 'HEAD~3..'
git log --oneline '..HEAD'
git log --oneline '^HEAD~2' HEAD
git rev-list --count 'HEAD~2..HEAD'
git rev-list 'HEAD~1..HEAD'
git rev-list --count '^HEAD~1' HEAD

echo '=== and the objects a range brings with it ==='
# What the far side of the range already holds is not named again, which
# is what makes this the list of what a pack for the range would carry.
git rev-list --objects HEAD | sort
git rev-list --objects 'HEAD~2..HEAD' | sort
git rev-list --objects '^HEAD~1' HEAD | sort

echo '=== ranges across branches ==='
git switch -q -c topic
printf 'topic\n' > t.txt
git add t.txt
git commit -q -m 'topic commit'
git switch -q main
printf 'more\n' >> b.txt
git add b.txt
git commit -q -m 'main moves on'
git log --oneline 'main..topic'
git log --oneline 'topic..main'
git rev-list --count 'main..topic'
git rev-list --count 'topic..main'

echo '=== pathspecs ==='
git log --oneline -- a.txt
git log --oneline -- b.txt
git log --oneline -- t.txt
git log --oneline -1 -- a.txt
git log --stat -1 -- a.txt
git log -p -1 -- b.txt
git log --oneline 'main..topic' -- t.txt
git log --name-status -2 -- b.txt

echo '=== the graph column ==='
git log --graph --oneline
git log --graph -2
git log --graph --stat -1
git log --graph -p -1 -- b.txt

echo '=== names that do not resolve ==='
git log --oneline 'HEAD~9..HEAD' || echo "bad range: $?"
git log --oneline nosuchrev || echo "bad revision: $?"
git rev-list nosuchrev || echo "bad rev-list: $?"
git rev-list --count '^nosuchrev' HEAD || echo "bad exclusion: $?"

# --parents puts what each commit came from on its line, merges included.
git rev-list --parents HEAD
git rev-list --parents --count HEAD
git rev-list --parents -2 HEAD
# and rev-parse names every ref there is, in ref order.
git rev-parse --all
git rev-parse --branches
git rev-parse --tags
git rev-parse --remotes

# Which of the commits found are shown: who made them, what they say, how
# many parents they have, and when. Dates are pinned to the second here,
# since a date git is told only the day of means that day at this time of
# it — which no two runs agree on.
git checkout -q -b filtered main
GIT_AUTHOR_NAME='Ada Writer' GIT_AUTHOR_EMAIL='ada@bash-os.test' \
GIT_AUTHOR_DATE='1750000200 +0000' GIT_COMMITTER_DATE='1750000200 +0000' \
    git commit -q --allow-empty -m 'Ada writes about packs'
GIT_AUTHOR_NAME='Bo Reader' GIT_AUTHOR_EMAIL='bo@bash-os.test' \
GIT_AUTHOR_DATE='1750000400 +0000' GIT_COMMITTER_DATE='1750000400 +0000' \
    git commit -q --allow-empty -m 'Bo writes about DATES
and a second line about packs'
GIT_AUTHOR_DATE='1750000600 +0000' GIT_COMMITTER_DATE='1750000600 +0000' \
    git commit -q --allow-empty -m 'the last of them'

echo '=== what they say ==='
git log --oneline --grep=packs
git log --oneline --grep=dates
git log --oneline -i --grep=dates
git log --oneline --grep=dates --grep=packs
git log --oneline --all-match --grep=DATES --grep=packs
git log --oneline --invert-grep --grep=packs -3
git log --oneline -E --grep='packs|last'
git log --oneline -F --grep='about packs'
git log --oneline --grep='^Ada'
git log --oneline --grep='packs$'
git log --oneline --grep=nothingatall

echo '=== who made them ==='
git log --oneline --author=Ada
git log --oneline --author='bash-os.test' -3
git log --oneline --author=Ada --grep=nothingatall
git log --oneline --committer='Parity Committer' -2

echo '=== how many parents ==='
git log --oneline --no-merges -3
git log --oneline --merges
git log --oneline --min-parents=1 -2
git log --oneline --max-parents=0
git rev-list --count --no-merges HEAD
git rev-list --count --grep=packs HEAD
git rev-list --max-count=2 --author=Ada HEAD

echo '=== and when ==='
git log --oneline --since=@1750000300
git log --oneline --until=@1750000300 -2
git log --oneline --since=@1750000300 --until=@1750000500
git log --oneline --since='2025-06-15 15:10:00' 
git checkout -q main
