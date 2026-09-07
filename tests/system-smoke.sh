#!/usr/bin/env bash
# Process/system imports: queries, temporary-file operations and child isolation.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BX=$(readlink -f "${1:-$HERE/out/bash}")
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
pass=0
B(){ "$BX" -c 'PATH=; "$@"' _ "$@"; }
check(){ "$@"; pass=$((pass+1)); }
status(){ local want=$1 rc=0; shift; "$@" >"$d/out" 2>"$d/err" || rc=$?; [[ $rc == "$want" ]]; }
check "$BX" -c 'PATH=; for t in "$@"; do [[ $(type -t "$t") == builtin ]] && help "$t" >/dev/null || exit 1; done' _ who w uptime lsof timeout signal hostid sysctl dmesg genl mlock utmp userdb keyctl caps cred ns xattr
check status 0 B timeout 1 true
check status 1 B timeout 1 false
check status 124 B timeout .05 sleep 2
check status 7 B timeout 1 /bin/sh -c 'exit 7'
check "$BX" -c 'PATH=; timeout 1 eval "exit 7"; [[ $? == 7 ]]; printf alive' >"$d/alive"
check test "$(cat "$d/alive")" = alive
check test "$(B signal -n TERM)" = 15
check test "$(B signal -s 15)" = TERM
check test "$(B sysctl -n kernel.ostype)" = "$(cat /proc/sys/kernel/ostype)"
check test "$(B sysctl kernel.ostype)" = "$(/usr/sbin/sysctl kernel.ostype)"
check status 1 B sysctl bash_os_test_missing_key
: > "$d/empty-utmp"
check status 0 B who "$d/empty-utmp"
check status 0 B utmp dump "$d/empty-utmp"
check status 0 B utmp boot "$d/wtmp"
check test -s "$d/wtmp"
check status 0 B uptime -p
check status 0 B w -h
check status 0 B lsof -p $$
check status 0 B mlock check
check status 0 B caps probe
check status 0 B cred status
check status 0 B ns list-ns
check "$BX" -c 'PATH=; userdb lookup root -V record && [[ $record == 0:0:* ]]'
printf 'data\n' >"$d/file"
check status 0 B xattr write "$d/file" user.bash_os value
check test "$(B xattr read "$d/file" user.bash_os)" = value
check status 0 B xattr remove "$d/file" user.bash_os
check status 1 B xattr read "$d/file" user.bash_os
printf 'system-smoke: %s passed\n' "$pass"
