#!/bin/bash
# Run only in a disposable VM with GNU df, mount, and unshare available.
# Usage: guest.sh /absolute/path/to/candidate-bash [dynamic-module]
set -eu
if [[ ${DF_INVENTORY_INNER:-} != 1 ]]; then
    export DF_INVENTORY_INNER=1
    exec unshare --mount --propagation private "$0" "$@"
fi
candidate=$1
module=${2:-}
work=$(mktemp -d)
trap 'umount -l "$work/bind" "$work/remote" "$work/local" 2>/dev/null || :; rm -rf "$work"' EXIT
mkdir "$work/local" "$work/remote" "$work/bind"
mount -t tmpfs -o size=1m local "$work/local"
mount -t tmpfs -o size=1m fixture:/export "$work/remote"
mount --bind "$work/local" "$work/bind"
# Ensure both sides see the same mounts before and after every pair.
mount_snapshot() { cat /proc/self/mountinfo; }
mount_snapshot >"$work/before"
run_pair() {
    local name=$1; shift
    set +e
    LC_ALL=C /usr/bin/df "$@" >"$work/ref.out" 2>"$work/ref.err"; local ref=$?
    LC_ALL=C "$candidate" --noprofile --norc -c '
        if [[ -n $1 ]]; then enable -f "$1" df || exit 125; fi
        shift
        df "$@"
    ' bash "$module" "$@" >"$work/candidate.out" 2>"$work/candidate.err"; local got=$?
    set -e
    mount_snapshot >"$work/after"
    cmp "$work/before" "$work/after" || { echo "$name: mount table changed" >&2; exit 1; }
    if [[ $ref != "$got" ]] || ! cmp -s "$work/ref.out" "$work/candidate.out" || ! cmp -s "$work/ref.err" "$work/candidate.err"; then
        echo "$name: reference status=$ref candidate status=$got" >&2
        diff -u "$work/ref.out" "$work/candidate.out" || :
        diff -u "$work/ref.err" "$work/candidate.err" >&2 || :
        exit 1
    fi
    echo "$name: ok"
}
run_pair default --output=source,fstype,target
run_pair all -a --output=source,fstype,target
run_pair types -t tmpfs -t ext4 --output=source,fstype,target
run_pair excluded -x tmpfs -x devtmpfs --output=source,fstype,target
run_pair local -l --output=source,fstype,target
run_pair local_operands -l --output=source,fstype,target "$work/local" "$work/remote"
run_pair no_match -t no-such-filesystem --output=target
