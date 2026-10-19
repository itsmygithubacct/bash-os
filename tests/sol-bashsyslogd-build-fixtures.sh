#!/bin/bash
# Run this compilation script through the campaign build gate.
set -euo pipefail
output=${1:?usage: sol-bashsyslogd-build-fixtures.sh OUTPUT_DIRECTORY}
mkdir -p "$output"
BT=build/bash-5.3
flags=(-fPIC -shared -Wl,-Bsymbolic -DHAVE_CONFIG_H -I"$BT" -I"$BT/include"
       -I"$BT/builtins" -I"$BT/examples/loadables")
cc -O2 -fPIC -shared tests/sol-bashsyslogd-faults.c -ldl -o "$output/faults.so"
cc -O2 "${flags[@]}" loadables/bashsyslogd.c -o "$output/bashsyslogd.so"
cc -O2 "${flags[@]}" tests/sol-bashsyslogd-alloc.c -o "$output/bashsyslogd-alloc.so"
cc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer "${flags[@]}" \
  tests/sol-bashsyslogd-alloc.c -o "$output/bashsyslogd-alloc-sanitize.so"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -fno-omit-frame-pointer -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" \
  -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/bashsyslogd.c -o "$output/bashsyslogd-sanitize.so"
cc -print-file-name=libasan.so > "$output/libasan.path"
