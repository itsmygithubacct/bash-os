#!/bin/sh
# One gated build job for the native companions and sanitizer/adapter tools.
# Usage: gated.py build -- sh tests/sol-pgrep-final-build.sh OUTPUT_DIR
set -eu
./build.sh --include pgrep,pkill,killall,killall5 --name sol-pgrep
sh tests/sol-pgrep-tools-build.sh "$1"
