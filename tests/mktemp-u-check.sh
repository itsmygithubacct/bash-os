#!/usr/bin/env bash
set -euo pipefail
BX=$(readlink -f "${1:-out/bash}")
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT

# -u must generate names without needing the target directory to exist.
"$BX" -e -c '
  PATH=
  file=$(mktemp -u "$1/missing/file.XXXXXX")
  [[ $file == "$1/missing/file."?????? ]]
  [[ ! -e "$1/missing" ]]
  dir=$(mktemp -d -u "$1/missing-dir.XXXXXX")
  [[ $dir == "$1/missing-dir."?????? ]]
  [[ ! -e $dir ]]
  regular=$(mktemp "$1/regular.XXXXXX")
  [[ -f $regular ]]
  regular_dir=$(mktemp -d "$1/regular-dir.XXXXXX")
  [[ -d $regular_dir ]]
' _ "$d"
printf 'mktemp -u: names generated without filesystem creation; ordinary creation preserved\n'
