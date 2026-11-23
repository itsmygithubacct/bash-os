#!/usr/bin/env bash
# A background command waits for exec before the shell goes on (the async
# exec handshake), but a redirection that opens a FIFO waits for the FIFO's
# other end, which the script may open only after the background start.
# The child must release the shell before that open.
# Usage: tests/async-fifo-redirect.sh BASH
set -u
BASH_UNDER_TEST=$(realpath "${1:-out/bash}") || exit 1
# External programs: bash-os runs its own cat and sleep as builtins, and a
# builtin releases the handshake on its own.
CAT=$(PATH=/usr/bin:/bin type -P cat) SLEEP=$(PATH=/usr/bin:/bin type -P sleep)
[[ -n $CAT && -n $SLEEP ]] || { echo 'not ok: no external cat/sleep'; exit 1; }
export CAT SLEEP
d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
fail=0
run() {
    local name=$1 script=$2 out
    if out=$(cd "$d" && timeout 20 "$BASH_UNDER_TEST" -c "$script" 2>&1) && [[ $out == ok ]]; then
        printf 'ok %s\n' "$name"
    else
        printf 'not ok %s: [%s]\n' "$name" "$out"; fail=1
    fi
}

# Input from a FIFO the script opens for writing afterwards.
run 'background < fifo, then open the writer' '
mkfifo in; "$CAT" < in > got & exec 9> in
echo hello >&9; exec 9>&-; wait
[[ $(< got) == hello ]] && echo ok'

# Output to a FIFO the script opens for reading afterwards.
run 'background > fifo, then open the reader' '
mkfifo out; printf hi > src; "$CAT" src > out & exec 9< out
read -r -u 9 line; exec 9<&-; wait
[[ $line == hi ]] && echo ok'

# The handshake itself still holds for an ordinary redirection: by the time
# the shell continues, $! is the program, not a shell copy.
run 'background > /dev/null has exec'"'"'d before $! is used' '
"$SLEEP" 5 > /dev/null & p=$!
c=$(< /proc/$p/comm); kill "$p"; wait "$p" 2>/dev/null
[[ $c == "${SLEEP##*/}" ]] && echo ok'

# A shell waiting on the handshake still dies of SIGTERM. The redirection
# word below expands in the child before exec, keeping the parent waiting;
# the EXIT trap makes bash catch SIGTERM rather than die of it.
start=$SECONDS
out=$(cd "$d" && timeout -s TERM 2 "$BASH_UNDER_TEST" -c '
trap "echo trapped" EXIT
"$CAT" < "$(sleep 8; echo /dev/null)" > /dev/null &
echo after' 2>&1); rc=$?
if (( rc == 124 && SECONDS - start < 6 )) && [[ $out == trapped ]]; then
    printf 'ok SIGTERM ends a shell waiting on the handshake\n'
else
    printf 'not ok SIGTERM ends a shell waiting on the handshake: rc=%s %ss [%s]\n' "$rc" "$((SECONDS - start))" "$out"; fail=1
fi

exit "$fail"
