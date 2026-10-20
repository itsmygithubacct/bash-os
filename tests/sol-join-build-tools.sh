#!/usr/bin/env bash
# Invoke through the build gate. Retain artifacts under the assigned evidence directory.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=$1
receipt=$2
BT="build/bash-$(. config/versions.sh; echo "$BASH_SRC_VERSION")"
incs=(-DHAVE_CONFIG_H -Iloadables/common -I"$BT" -I"$BT/include" -I"$BT/builtins" -I"$BT/examples/loadables")
case $mode in
  rusage) cc -O2 -Wall -Wextra tests/sol-join-rusage.c -o "$receipt" ;;
  profile) cc -O2 -g -fPIC -shared -Wl,-Bsymbolic -finstrument-functions "${incs[@]}" tests/sol-join-profile.c -o "$receipt" ;;
  sanitize) cc -O1 -g -no-pie -fsanitize=address,undefined -fno-omit-frame-pointer "${incs[@]}" tests/sol-join-sanitize.c -o "$receipt" ;;
  *) exit 2 ;;
esac
