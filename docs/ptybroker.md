# Persistent local PTYs

`ptybroker` starts an independent process that owns a PTY and its children.
The creating Bash and attached clients can exit without terminating that PTY.
`screen` uses these services for its live windows and panes. Both commands
are included in the desktop and full profiles.

For a small build with just the relevant commands:

```sh
./build.sh --include ptybroker,screen,pty,bashpoll --name terminal
out/bash-terminal
```

The local service needs Linux `/proc`, Unix `SOCK_SEQPACKET`, subreapers and
pidfd system calls. Its clean process launcher uses GNU `posix_spawn`
extensions. There are no GPU or terminal-parser dependencies in `ptybroker`.
`screen` retains its existing optional SSH support and associated libraries.
Selective builds must include the `ptybroker` companion when selecting `screen`.

## Commands

Use a short, absolute runtime directory. Its permissions must be 0700 and
its owner must match the effective user. New roots are created with those
permissions. IDs contain letters, digits, dot, underscore or dash, are at
most 48 bytes, and cannot start with a dot. The complete
`ROOT/ID/control.sock` path must fit a Unix socket address (107 bytes).

```bash
root=/tmp/my-pty-sessions
ptybroker create "$root" demo --rows 24 --cols 80 -- "$BASH" --noprofile --norc
ptybroker status "$root" demo
ptybroker list "$root"
ptybroker attach "$root" demo control handle
ptybroker fd "$handle" ready_fd
ptybroker send "$root" demo $'printf "hello\\n"\n'

# Metadata is assigned to event; output bytes go directly to FD 1.
while ptybroker receive "$handle" 1 event 250; do
    printf 'event: %s\n' "$event"
done

ptybroker detach "$handle"
ptybroker resize "$root" demo 30 100
exec 7>history.bin
ptybroker capture "$root" demo 7
exec 7>&-
ptybroker terminate "$root" demo
```

`create` accepts `--cwd DIRECTORY` before `--`. Without it, the child starts
in the caller's current directory. The command after `--` is a literal argv;
shell evaluation requires explicitly selecting a shell and its `-c` option.
The service executes the current Bash binary in a fresh process with startup
hooks, imported functions and unrelated file descriptors removed. Loading
`ptybroker.so` with `enable -f` also works: the creator resolves that object's
path for the fresh shell. `BASH_PTYBROKER_LOADABLE` can supply an explicit
absolute shared-object path. An unavailable executable or object is an error.

`status` prints `key=value` fields: broker and child PIDs, child running and
exit status, stopping state, geometry, controller/observer counts and the
oldest/next byte offsets. Capability fields identify a raw PTY with no replay.
Child status is retained until `terminate`; `running=0` does not assert that
all descendants have stopped. `terminate` waits for descendant cleanup and
removes the owned socket and session directory before acknowledging.
The service continues TERM-to-KILL escalation after the original child exits,
including adopted descendants that started their own sessions.

## Streams and events

An attachment has one of two roles: `control` or `observe`. A session allows
one controller and eight observers. Both receive live output; observers
cannot send control packets on their subscription. Administrative commands
such as `send` and `resize` use separate authenticated connections. Roles do
not isolate programs running as the same user.

Handles belong to the creating Bash process and have generations. Subshells,
closed handles and handles from an earlier shared-object load are rejected.
The FD returned by `fd` is borrowed for readiness polling: do not close,
replace or read it directly. Use `detach` to close an attachment.

`receive HANDLE OUTFD EVENTVAR [TIMEOUT_MS]` returns one event. Its default
timeout is 100 ms, its maximum is 60,000 ms, and timeout returns 124. Event
names are `attached`, `gap`, `output`, `geometry` and `exit`, followed by
small typed fields. `output` includes byte count and stream offset; only its
payload is written to OUTFD. Partial writes retain their remaining bytes for
the next call on that handle. `exit` follows the final PTY output; the original
child's exit status can become available earlier through `status`.

`send-fd ROOT ID INFD [COUNT_VAR]` consumes at most 16,384 bytes per call,
preserving NUL and non-UTF-8 bytes. COUNT_VAR reports the accepted count;
zero means input EOF. Repeat for larger input. Output variables must be
writable scalars. An I/O failure may occur after input was consumed or after
the server accepted it, so failed sends are not safe to retry blindly.

Server queues are bounded: 1 MiB of pending PTY input, 256 KiB of queued
output per subscriber, and 1 MiB of raw history per session. A slow subscriber
is disconnected before its output can stall the service. A later attachment
starts at the current byte offset and reports a gap when history exists.
Idle unauthenticated requests have a short deadline; malformed or oversized
packets are discarded by closing that connection. The endpoint is local and
checks peer credentials; no network listener or credential file is used.

## History and terminal state

Attach never replays history into a terminal. This prevents an old terminal
query from generating a new application reply. A controlling attach requests
a foreground redraw, including when geometry has not changed. Applications
that do not redraw on SIGWINCH may need an application-specific refresh.

`capture` is the explicit raw-history operation. Its bounded in-memory ring
cannot fail because a journal disk fills. Overwrite advances `oldest`; capture
returns an overflow error if the requested range is overwritten during the
copy. Captured bytes may begin inside an escape sequence and are not a parsed
screen, a graphics checkpoint or a sequence safe to replay automatically.

This service does not answer terminal queries while detached, maintain a
terminal grid, preserve Kitty/Sixel image state, or recover across broker
death/reboot. A graphical frontend needs an authoritative terminal-state
service to provide those capabilities. Do not feed capture bytes into a live
parser whose replies are connected to the application.

## Live screen panes

```bash
screen run -n work
screen pane-split work 0 h
screen send-keys work -p 0:1 'printf "second pane\n"'
screen pane-resize work 0 1 '0 40 24 40'
screen capture-pane work -p 0:1
screen attach work
screen kill work
```

Default shells and `screen run -c` commands use the current Bash executable.
`win-create` and `pane-split` accept literal commands after `--`.
Focus determines untargeted input; explicit pane targets send to that pane's
real PTY. Resize and swap update the actual PTY geometry. Attach follows the
active pane, and its detach key remains Ctrl-A then D. `attach -x` observes.
Capture/state/VT metadata explicitly describe raw output, not a parsed grid.

`screen run --metadata` explicitly selects the previous offline layout
scaffolding for consumers that need metadata without child processes.
Live kill operations use broker identity and completion, never a PID file as
signal authority. Layout mutations are serialized, and failed creation rolls
back the new pane and service.

## Verification

```sh
python3 tests/ptybroker.py --bash out/bash-terminal
python3 tests/ptybroker-io.py --bash out/bash-terminal
python3 tests/screen-broker.py --bash out/bash-terminal
python3 tests/pty-primitives.py out/bash-terminal
```

Tests create private services and check real PTY processes, binary streams,
frontend loss, observer pressure, malformed requests, output failures,
startup cancellation, concurrent statuses, geometry and descendant cleanup.
The broker suite also accepts `--loadable FILE`; screen's suite accepts a
`--load-dir` containing linked `ptybroker.so` and `screen.so` modules.
