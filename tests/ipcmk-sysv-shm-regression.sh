#!/usr/bin/env bash
# Run only in a disposable VM as uid 2000, with a prebuilt kernel oracle.
# Invoke as: candidate-bash --noprofile --norc tests/ipcmk-sysv-shm-regression.sh ORACLE.so
set -u
export LC_ALL=C
[[ $EUID == 2000 ]] || { echo 'requires uid 2000' >&2; exit 90; }
[[ $# == 1 ]] || exit 90
enable -f "$1" ipcmk_check || exit 90
[[ $(type -t ipcmk) == builtin ]] || exit 90
work=$(/usr/bin/mktemp -d) || exit 90
trap '/usr/bin/rm -rf -- "$work"' EXIT
umask 077
check_shm() {
    local mode=$1; shift
    ipcmk "$@" >"$work/out" || return 1
    # Oracle validates the exact record, IPC_PRIVATE, size, owner/creator,
    # mode and nattch, removes this ID only, then verifies it is absent.
    ipcmk_check shm "$work/out" 4096 "$mode"
}
check_shm 600 -M 4096 -p 0600 || exit 1
check_shm 644 -M 4096 || exit 1
check_shm 600 -M4096 -p0600 || exit 1
check_shm 600 --shmem=4096 --mode=0600 || exit 1
reject() {
    if ipcmk "$@" >"$work/out" 2>"$work/err"; then
        echo "unexpected success: $*" >&2
        return 1
    fi
    [[ ! -s $work/out && -s $work/err ]]
}
reject -M x || exit 1
reject -M 0 || exit 1
reject -S x || exit 1
reject -S 0 || exit 1
reject -M 4096 -p 999 || exit 1
reject -M 4096 --mode=x || exit 1
reject || exit 1
reject -Q -M 4096 || exit 1
reject -Z || exit 1
reject -M || exit 1
reject -p 0600 || exit 1
printf '%s\n' 'sysv shared memory contract verified'
