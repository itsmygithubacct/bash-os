#!/usr/bin/env bash
# The git builtin and its helpers under ASan and UBSan. The line diff, the
# patch writer and the index and tree readers all walk memory they built
# from file content, so they are exercised here with the shapes that reach
# the edges: a long file changed in many places, a file with no trailing
# newline, a binary file, a path that has to be quoted, and every command
# that reads the working tree.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd); cd "$HERE"
CC=${CC:-cc}
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
[[ -d $BT ]] || { echo 'git-sanitize: build tree missing; run ./build.sh first'; exit 1; }
target=$(realpath "${1:-out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/helpers/builtins" "$d/helpers/examples/loadables"
python3 config/stage-helpers.py --stage "$HERE" "$d/helpers" git >/dev/null
HB="$d/helpers/builtins"

"$CC" -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" -I"$BT/builtins" \
  -I"$BT/examples/loadables" -I"$HB" -Iloadables/common \
  loadables/git.c "$HB"/_git_*.c -lz -lm -o "$d/git.so"

repo=$d/repo
mkdir -p "$repo"
cat > "$d/scenario.sh" <<'SCENARIO'
set -e
enable -f "$GIT_SO" git
git init -q -b main .

# A long file, so the diff has real work to do, changed in several places.
: > long.txt
for i in {1..400}; do printf 'line %d of the long file\n' "$i" >> long.txt; done
printf 'no newline here' > ragged.txt
printf 'binary\000content\000here\n' > blob.bin
printf 'x\n' > 'a path with spaces and "quotes".txt'
mkdir -p nest/deeper
printf 'nested\n' > nest/deeper/file.txt
git add .
git commit -q -m 'the first commit'

for i in 7 61 199 200 201 398; do
  sed -i "${i}s/.*/line $i changed, and lengthened a little/" long.txt
done
printf 'line 401 appended\n' >> long.txt
printf 'no newline here either, but different' > ragged.txt
printf 'binary\000other\000bytes\n' > blob.bin
git diff
git diff --stat
git diff --numstat
git diff --shortstat
git diff -U0
git diff -U7
git diff --name-status
git status
git status --short
git status --porcelain=v2 --branch
git add -A
git diff --cached
git commit -m 'the second commit'
git log -p
git log --stat
git log --oneline -p
git show
git show HEAD~1
git show 'HEAD:long.txt' > /dev/null
git show 'HEAD:'
git show HEAD^{tree} > /dev/null

# Branching, switching and resetting, which rewrite the working tree.
git branch topic
git switch -q topic
printf 'on the topic branch\n' > topic.txt
git add topic.txt
git commit -q -m 'a topic commit'
git switch -q main
git diff main topic
git diff --stat main topic
git reset -q --hard HEAD~1
git status
git checkout -q topic -- topic.txt || true
git restore --staged . || true
git tag -a v1 -m 'a tag'
git show v1 > /dev/null
git rm -q --cached ragged.txt
git status --short

# Moving tracked paths and sweeping untracked ones.
git mv long.txt renamed-long.txt
git mv -n renamed-long.txt nest/
git mv renamed-long.txt nest/
git mv nest/deeper other-deeper
git status --short --no-renames
printf 'sweep me\n' > sweep.txt
mkdir -p sweepdir
printf 'x\n' > sweepdir/x.txt
git clean -nd
git clean -fdx
git log --oneline 'topic~1..topic'
git log --oneline -- nest
git rev-list --count '^topic~1' topic
git log --oneline nosuchrev 2>/dev/null || true   # the error path, quietly
git log --graph --oneline
git log --graph -p -1
git merge-base topic main
git merge-base --is-ancestor main topic || true
git merge-base --independent topic main
git merge-base --octopus topic main

# The three-way merge of one file's three versions.
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > base-file
printf 'ONE\ntwo\nthree\nfour\nfive\nsix\nseven\neight\n' > our-file
printf 'one\ntwo\nthree\nfour\nfive\nsix\nseven\nEIGHT\n' > their-file
git merge-file -p our-file base-file their-file
printf 'one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\n' > our-file
printf 'one\ntwo\ndrei\nfour\nFIVE\nsix\nseven\neight\n' > their-file
git merge-file -p -L ours -L base -L theirs our-file base-file their-file || true
git merge-file our-file base-file their-file || true
: > empty-file
git merge-file -p our-file empty-file their-file || true
git reflog > /dev/null
git fsck 2>/dev/null || true
SCENARIO

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
LD_PRELOAD=$("$CC" -print-file-name=libasan.so) \
GIT_SO="$d/git.so" \
GIT_CONFIG_NOSYSTEM=1 HOME="$d" LC_ALL=C TZ=UTC \
GIT_AUTHOR_NAME='Sanitize Author' GIT_AUTHOR_EMAIL=author@bash-os.test \
GIT_AUTHOR_DATE='1750000000 +0000' \
GIT_COMMITTER_NAME='Sanitize Committer' GIT_COMMITTER_EMAIL=committer@bash-os.test \
GIT_COMMITTER_DATE='1750000100 +0000' \
  "$target" --noprofile --norc -c "cd '$repo' && . '$d/scenario.sh'" > "$d/out" 2> "$d/err" \
  || { tail -5 "$d/out"; cat "$d/err" >&2; echo 'git-sanitize: the scenario stopped early'; exit 1; }

if grep -qE 'runtime error|AddressSanitizer|LeakSanitizer' "$d/err"; then
  cat "$d/err"
  echo 'git-sanitize: sanitizer reported a problem'
  exit 1
fi
# The scenario itself must have run clean: git says nothing on stderr here
# except what the commands are meant to say.
if grep -qE '^(fatal|usage):' "$d/err"; then
  cat "$d/err"
  echo 'git-sanitize: a command failed'
  exit 1
fi
lines=$(wc -l < "$d/out")
echo "git-sanitize: instrumented git ran the scenario clean ($lines lines of output)"
