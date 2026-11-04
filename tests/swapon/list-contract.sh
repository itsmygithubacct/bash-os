#!/bin/bash
# Run only as root in a disposable VM with a private mount namespace.
# Usage: list-contract.sh /absolute/path/to/bash [absolute/path/to/swapon.so]
set -eu
export LC_ALL=C
candidate=${1:?candidate Bash required}
module=${2-}
work=$(mktemp -d)
mounted=0
cleanup() {
    if (( mounted )); then umount /proc/swaps; fi
    rm -rf "$work"
}
trap cleanup EXIT
invoke() {
    "$candidate" --noprofile --norc -c '
        module=$1; shift
        if [[ -n $module ]]; then enable -f "$module" swapon || exit 98; fi
        [[ $(type -t swapon) == builtin ]] || exit 99
        swapon "$@"
    ' swapon-test "$module" "$@"
}
check_table() {
    local oracle=$1 label=$2 alias rc
    for alias in default -s --show --summary; do
        rc=0
        if [[ $alias == default ]]; then
            invoke >"$work/out" 2>"$work/err" || rc=$?
        else
            invoke "$alias" >"$work/out" 2>"$work/err" || rc=$?
        fi
        if (( rc != 0 )) || [[ -s $work/err ]] || ! cmp -s "$oracle" "$work/out"; then
            printf 'FAIL %s %s status=%s\n' "$label" "$alias" "$rc" >&2
            cat "$work/err" >&2
            return 1
        fi
    done
}
# Read the actual table independently, without command substitution stripping newlines.
cat /proc/swaps >"$work/actual"
check_table "$work/actual" actual
printf 'Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n' >"$work/fixture"
mount --bind "$work/fixture" /proc/swaps
mounted=1
check_table "$work/fixture" header-only
umount /proc/swaps
mounted=0
printf '/swap/a file 1024 12 5\n/dev/sdb1 partition 2048 0 3\n' >>"$work/fixture"
mount --bind "$work/fixture" /proc/swaps
mounted=1
check_table "$work/fixture" two-rows
umount /proc/swaps
mounted=0
: >"$work/denied"
chmod 000 "$work/denied"
mount --bind "$work/denied" /proc/swaps
mounted=1
rc=0
setpriv --bounding-set=-dac_override,-dac_read_search -- "$candidate" --noprofile --norc -c '
    module=$1
    if [[ -n $module ]]; then enable -f "$module" swapon || exit 98; fi
    [[ $(type -t swapon) == builtin ]] || exit 99
    swapon --show
' swapon-test "$module" >"$work/out" 2>"$work/err" || rc=$?
if (( rc != 1 )) || [[ -s $work/out ]] || ! LC_ALL=C grep -Fq '/proc/swaps: Permission denied' "$work/err"; then
    printf 'FAIL open-error status=%s\n' "$rc" >&2
    cat "$work/err" >&2
    exit 1
fi
printf 'PASS swapon-list-contract\n'
