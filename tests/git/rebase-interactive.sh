#!/usr/bin/env bash
# Going over a branch's own commits: the todo list git writes, what an
# editor may make of it, and what each command in it does — picking,
# dropping, rewording, melding, running something, stopping to amend.
# The two editors here are scripts: one copies a prepared list over the
# todo, the other writes whatever $MESSAGE says.
# Run through tests/git-parity.py, never on its own.
# requires: init add commit rebase log reset status
set -e

printf '%s\n' '#!/bin/sh' \
  'while IFS= read -r line; do printf "%s\n" "$line"; done < "$TODO_FILE" > "$1"' \
  > sequence-editor
printf '%s\n' '#!/bin/sh' \
  'printf "%s\n" "$MESSAGE" > "$1"' > message-editor
chmod 755 sequence-editor message-editor
export GIT_SEQUENCE_EDITOR=./sequence-editor
export GIT_EDITOR=./message-editor
export TODO_FILE=planned-todo

git init -q -b main .
# A file each, so that leaving one out or moving one does not make the
# next one conflict: what is being looked at here is the list, not the
# merging.
for i in 1 2 3 4; do
  printf 'file %d\n' "$i" > "f$i.txt"
  git add "f$i.txt"
  git commit -q -m "commit $i"
done
start=$(git rev-parse HEAD)
two=$(git log --format='%h %s' -1 HEAD~2)
three=$(git log --format='%h %s' -1 HEAD~1)
four=$(git log --format='%h %s' -1)

again() {
  git reset -q --hard "$start"
}

echo '=== the list git writes ==='
printf 'pick %s\npick %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3
git log --oneline
cat .git/rebase-merge/git-rebase-todo 2>/dev/null || echo 'nothing left behind'

echo '=== dropping one ==='
again
printf 'pick %s\npick %s\n' "$two" "$four" > planned-todo
git rebase -i HEAD~3
git log --format='%s'

echo '=== rewording one ==='
again
printf 'reword %s\npick %s\npick %s\n' "$two" "$three" "$four" > planned-todo
MESSAGE='commit 2, said again' git rebase -i HEAD~3
git log --format='%s'

echo '=== melding one into the one before it ==='
again
printf 'pick %s\nfixup %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3
git log --format='%s'
ls

echo '=== melding with a message of its own ==='
again
printf 'pick %s\nsquash %s\npick %s\n' "$two" "$three" "$four" > planned-todo
MESSAGE='two and three together' git rebase -i HEAD~3
git log --format='%s'

echo '=== running something in the middle ==='
again
printf 'pick %s\nexec printf "ran here\\n"\npick %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3
git log --format='%s' -1

echo '=== and something that fails ==='
again
printf 'pick %s\nexec false\npick %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3 || echo "rebase said no: $?"
git status --short
git rebase --continue
git log --format='%s' -1

echo '=== stopping to look around ==='
again
printf 'pick %s\nbreak\npick %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3
git log --format='%s'
git rebase --continue
git log --format='%s' -1

echo '=== stopping to amend ==='
again
printf 'pick %s\nedit %s\npick %s\n' "$two" "$three" "$four" > planned-todo
git rebase -i HEAD~3
git log --format='%s'
printf 'an extra file\n' > extra.txt
git add extra.txt
MESSAGE='commit 3, with something else in it' git rebase --continue
git log --format='%s'
git show --stat --format='%s' HEAD~1

echo '=== and a list with nothing left in it ==='
again
printf '# nothing here\n' > planned-todo
git rebase -i HEAD~3 || echo "rebase said no: $?"
git log --format='%s' -1
git status --short
