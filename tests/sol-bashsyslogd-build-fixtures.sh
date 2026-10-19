#!/bin/bash
# Run this compilation script through the campaign build gate.
set -euo pipefail
output=${1:?usage: sol-bashsyslogd-build-fixtures.sh OUTPUT_DIRECTORY}
BT=build/bash-5.3
cc -O2 -fPIC -shared tests/sol-bashsyslogd-faults.c -ldl -o "$output/faults.so"
cc -O1 -g -fPIC -shared -Wl,-Bsymbolic -fsanitize=address,undefined \
  -fno-omit-frame-pointer -DHAVE_CONFIG_H -I"$BT" -I"$BT/include" \
  -I"$BT/builtins" -I"$BT/examples/loadables" \
  loadables/bashsyslogd.c -o "$output/bashsyslogd-sanitize.so"
