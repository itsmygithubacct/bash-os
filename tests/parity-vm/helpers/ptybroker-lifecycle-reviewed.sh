# Guest-only candidate driver; sourced by the parity candidate shell.
H=/opt/bashos-parity/harness/helpers/ptybroker-lifecycle-reviewed.py
root=$HOME/broker-root
export LC_ALL=C
/usr/bin/python3 -I "$H" guard || exit 125
ulimit -f 256 || exit 125
/usr/bin/mkdir -m 700 "$root" || exit 125
: >"$HOME/candidate-stdout"
: >"$HOME/candidate-stderr"
: >"$HOME/candidate-steps"; : >"$HOME/candidate-polls"
: >"$HOME/candidate-events"
: >"$HOME/candidate-live.bin"
: >"$HOME/candidate-capture.bin"
: >"$HOME/candidate-before"
: >"$HOME/candidate-after"
active=0
cleanup() { if (( active )); then ptybroker terminate "$root" one >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; printf 'trap_terminate=%s\n' "$?" >>"$HOME/candidate-steps"; fi; }
trap cleanup EXIT
ptybroker create "$root" one -- /usr/bin/python3 -I "$H" child >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'create=%s\n' "$rc" >>"$HOME/candidate-steps"
if (( rc != 0 )); then /usr/bin/python3 -I "$H" check; exit 1; fi
active=1
ready=0
# Polling asks the broker for its processed byte offset; the child marker alone
# is not evidence that the broker has read the PTY. No delay proves ordering.
deadline=$(/usr/bin/python3 -I "$H" deadline 2>>"$HOME/candidate-stderr") || exit 125
while /usr/bin/python3 -I "$H" before "$deadline" 2>>"$HOME/candidate-stderr"; do
    ptybroker status "$root" one >"$HOME/candidate-before" 2>>"$HOME/candidate-stderr"; rc=$?
    printf 'candidate-before rc=%s ' "$rc" >>"$HOME/candidate-polls"; /usr/bin/cat "$HOME/candidate-before" >>"$HOME/candidate-polls"
    if (( rc == 0 )) && [[ -f $HOME/child-ready ]] && [[ $(<"$HOME/candidate-before") == *' oldest=0 next=12 '* ]]; then ready=1; break; fi
    /usr/bin/sleep .05
done
printf 'ready=%s\n' "$ready" >>"$HOME/candidate-steps"
if (( ! ready )); then /usr/bin/python3 -I "$H" check; exit 1; fi
ptybroker attach "$root" one observe h >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'attach=%s\n' "$rc" >>"$HOME/candidate-steps"
if (( rc != 0 )); then /usr/bin/python3 -I "$H" check; exit 1; fi
exec 8>"$HOME/candidate-live.bin"
# Drain attached/gap before releasing the child.
for ((i=0; i<2; i++)); do
    ev=''
    ptybroker receive "$h" 8 ev 3000 >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
    printf '%s|%s\n' "$rc" "$ev" >>"$HOME/candidate-events"
    if (( rc != 0 )); then printf 'receive_initial=%s\n' "$rc" >>"$HOME/candidate-steps"; /usr/bin/python3 -I "$H" check; exit 1; fi
done
ptybroker send "$root" one G >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'send_g=%s\n' "$rc" >>"$HOME/candidate-steps"
if (( rc != 0 )); then /usr/bin/python3 -I "$H" check; exit 1; fi
# The first complete live payload is observed before requesting final output.
total=0
for ((i=0; i<32 && total<11; i++)); do
    ev=''
    ptybroker receive "$h" 8 ev 3000 >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
    printf '%s|%s\n' "$rc" "$ev" >>"$HOME/candidate-events"
    if (( rc != 0 )); then printf 'receive_live=%s\n' "$rc" >>"$HOME/candidate-steps"; /usr/bin/python3 -I "$H" check; exit 1; fi
    if [[ $ev =~ ^output\ size=([0-9]+)\ offset=([0-9]+)$ ]]; then ((total+=BASH_REMATCH[1])); else break; fi
done
ptybroker send "$root" one E >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'send_e=%s\n' "$rc" >>"$HOME/candidate-steps"
if (( rc != 0 )); then /usr/bin/python3 -I "$H" check; exit 1; fi
receive=1
for ((i=0; i<32; i++)); do
    ev=''
    ptybroker receive "$h" 8 ev 3000 >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
    printf '%s|%s\n' "$rc" "$ev" >>"$HOME/candidate-events"
    if (( rc != 0 )); then receive=$rc; break; fi
    if [[ $ev == exit\ * ]]; then receive=0; break; fi
done
printf 'receive=%s\n' "$receive" >>"$HOME/candidate-steps"
exec 8>&-
ptybroker status "$root" one >"$HOME/candidate-after" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'status=%s\n' "$rc" >>"$HOME/candidate-steps"
exec 8>"$HOME/candidate-capture.bin"
ptybroker capture "$root" one 8 >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
exec 8>&-
printf 'capture=%s\n' "$rc" >>"$HOME/candidate-steps"
ptybroker detach "$h" >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'detach=%s\n' "$rc" >>"$HOME/candidate-steps"
ptybroker terminate "$root" one >>"$HOME/candidate-stdout" 2>>"$HOME/candidate-stderr"; rc=$?
printf 'terminate=%s\n' "$rc" >>"$HOME/candidate-steps"
if (( rc == 0 )); then active=0; fi
/usr/bin/python3 -I "$H" check
exit $?
