# timeout

`timeout` runs a command with a time limit. Exit 124 on timeout, 125 on
internal error, 126 if the command is found but not executable, 127 if
not found, 128+N if killed by signal N, otherwise the command's own
status. Duration 0 disables the limit and still runs the command.

`SIGCHLD` is blocked while waiting so Bash cannot reap the timeout child,
but the wait must not dequeue that signal. A pidfd/`ppoll` (or
`clock_nanosleep` of the remaining time if pidfd is unavailable) wakes
without `sigtimedwait`. After the child is collected, the previous mask
is restored so a leftover `SIGCHLD` still reaches Bash: a background job
that exited during the wait is reaped, and a `CHLD` trap can run.

```sh
./build.sh --include timeout --name timeout
out/bash-timeout -c 'PATH=; timeout 1 true'
```

`tests/timeout-check.sh` checks the statuses above, duration 0, and that
a background `sleep` is reaped while `timeout` still waits for its own
child.
