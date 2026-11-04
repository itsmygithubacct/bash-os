#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run only in a disposable VM, as uid 2000, with the test oracle built separately.
set -u
[[ $# == 2 && $EUID == 2000 ]] || { echo 'need oracle, output directory and uid 2000' >&2; exit 98; }
enable -f "$1" ipcmk_check || exit 98
[[ $(type -t ipcmk) == builtin ]] || exit 98
export LC_ALL=C
out=$2/sem.out
err=$2/sem.err

check_create() {
    local count=$1 mode=$2; shift 2
    ipcmk "$@" >"$out" || return 1
    # The oracle checks the exact output, IPC_PRIVATE, count, mode, owner and
    # creator, then removes only that returned id and confirms its absence.
    ipcmk_check sem "$out" "$count" "$mode"
}
check_invalid() {
    local status=0
    ipcmk "$@" >"$out" 2>"$err" || status=$?
    [[ $status == 1 && ! -s $out && -s $err ]]
}

check_create 2 600 -S 2 -p 0600 || exit 10
check_create 1 644 -S 1 || exit 11
check_create 3 640 -S3 -p0640 || exit 12
check_create 4 600 --semaphore=4 --mode=0600 || exit 13
check_invalid -S x || exit 20
check_invalid -S 0 || exit 21
check_invalid -S 1 -p 8 || exit 22
check_invalid -M x || exit 23
check_invalid || exit 24
check_invalid -Q -S 2 || exit 25
check_invalid -Z || exit 26
check_invalid -S || exit 27
printf 'owned semaphore checks passed\n'
