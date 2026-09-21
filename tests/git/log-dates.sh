#!/usr/bin/env bash
# A date is written the way --date= asks for it, and a commit carries the
# names that point at it the way --decorate asks. Every mode is compared
# here except the two that count from the moment of the run — relative and
# human — which no two runs agree on.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit tag branch update-ref log show checkout
set -e

git init -q -b main .
echo one > f.txt
git add f.txt
GIT_AUTHOR_DATE='1751500800 +0530' GIT_COMMITTER_DATE='1751500800 +0530' \
    git commit -q -m 'the third of July, half past five, east of here'
git tag v1
git tag -a v1a -m 'an annotated tag'
git branch side
git update-ref refs/remotes/origin/main HEAD

echo two > f.txt
GIT_AUTHOR_DATE='1720000000 -0700' GIT_COMMITTER_DATE='1720000000 -0700' \
    git commit -q -am 'and one from the west'
echo three > f.txt
git commit -q -am 'and one in the zone the harness pins'

echo '=== every mode, in the zone each commit recorded ==='
for mode in default raw iso iso8601 iso-strict iso8601-strict short unix \
            rfc rfc2822; do
    echo "--- $mode"
    git log --date=$mode --format='%ad|%cd'
done

echo '=== and the same, read off the clock in front of the reader ==='
for mode in local default-local iso-local iso-strict-local short-local \
            raw-local; do
    echo "--- $mode"
    git log --date=$mode --format='%ad'
done

echo '=== which is a different clock over there ==='
TZ='XYZ-5:30' git log --date=local --format='%ad' -1
TZ='XYZ-5:30' git log --date=iso-local --format='%ad' -1
TZ='ABC7' git log --date=iso-strict-local --format='%ad' -1
TZ='ABC7' git log --date=default-local --format='%ad' -1

echo '=== a pattern of the caller own ==='
git log --date='format:%Y-%m-%d %H:%M:%S %z' --format='%ad'
TZ='XYZ-5:30' git log --date='format-local:%Y/%j %H%M' --format='%ad' -1

echo '=== the placeholders that name a mode themselves ==='
git log --format='%at|%ai|%aI|%as'
git log --format='%ct|%ci|%cI|%cs'

echo '=== written as two words, and one nobody knows ==='
git log --date short --format='%ad' -1
git log --date=nonsense -1 || echo "said no: $?"

echo '=== what points at these commits ==='
git log --oneline --decorate
git log --oneline --decorate=full
git log --oneline --decorate=short
git log --oneline --decorate=no
git log --oneline --no-decorate
git log --oneline --decorate=auto
git log --decorate -1
git log --decorate=full -1
git log --format='%d' --decorate=full
git log --format='%D' --no-decorate
git log --oneline --decorate=sideways || echo "said no: $?"

echo '=== and with HEAD standing on nothing ==='
git checkout -q --detach HEAD
git log --oneline --decorate -2
git show -s --oneline --decorate
git checkout -q main
git log --oneline --decorate -1
