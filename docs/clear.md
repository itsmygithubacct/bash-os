# Clearing the terminal

`clear` and `bashclear` are identical builtins. Both are included in `core`,
`device`, `server`, `desktop` and `full`, and work with an empty `PATH` in
static builds without external programs or terminal database files.

```sh
clear                    # clear the screen and supported scrollback
clear -x                 # keep scrollback
bashclear -T xterm        # override TERM for this invocation
help clear
clear -V                 # bashclear's version
```

Syntax: `clear [-x] [-T TERM] | -V | --version | --help`. `bashclear` accepts
the same options. Short options may be combined; `-Txterm` is accepted.
`--` ends options, and operands are rejected. `-V` and `--help` exit immediately.

`-T` overrides the shell variable `TERM`. An unexported `TERM` works too;
temporary assignments such as `TERM=linux clear` do not change later calls.
An unset or empty `TERM`, or an unsupported name, produces a diagnostic and
status 1 without writing control bytes. `TERM=dumb` returns 1 silently.
Use `-T` when the terminal type is known but the environment is incomplete.

Output goes to **standard output**, even when redirected, with no newline.
The command leaves input, terminal modes, colors, and the alternate screen
unchanged. It homes the cursor before erasing. It does not perform a terminal
reset. For example, this captures bytes without clearing a terminal:

```sh
clear -T xterm > clear.bytes
```

The built-in table uses these sequences (`ESC` is byte `0x1b`):

| Terminal names | Visible screen | Scrollback, unless `-x` |
| --- | --- | --- |
| `xterm`, `xterm-256color`, `alacritty`, `foot`, `foot-direct` | `ESC[H ESC[2J` | `ESC[3J` |
| `xterm-color`, `xterm-kitty`, `screen.xterm-256color`, `rxvt`, `rxvt-unicode`, `rxvt-unicode-256color`, `st`, `st-256color` | `ESC[H ESC[2J` | None |
| `screen`, `screen-256color`, `vt100`, `vt102`, `vt220`, `ansi` | `ESC[H ESC[J` | None |
| `tmux`, `tmux-256color`, `linux` | `ESC[H ESC[J` | `ESC[3J` |

Spaces in the table separate sequences for readability; none are emitted.
Names are matched exactly, without prefix guessing. Scrollback behavior
follows the capabilities in this table, even if an emulator also understands
other sequences.

## Compatibility and status

The options and screen/scrollback distinction follow
[ncurses clear](https://invisible-island.net/ncurses/man/clear.1.html).
This is a fixed terminal table, not a full ncurses implementation. It ignores
`TERMINFO`, `TERMINFO_DIRS`, `TERMCAP`, the `tput` sidecar settings, `LINES` and
`COLUMNS`. Custom terminal definitions and compiled terminfo entries do not
override it. For other terminals, select a listed compatible type explicitly.

VT100/VT102 output omits serial-line padding: ncurses may append NUL bytes or
delay according to the output baud rate. bashclear emits only the visible
control sequence. It is intended for terminal emulators; actual slow serial
terminals can require padding. Installed ncurses databases can also differ
in their clear and scrollback capabilities.

| Status | Meaning |
| --- | --- |
| 0 | Bytes written successfully, or help/version printed |
| 1 | Output error, unset/empty/unsupported terminal type, or `dumb` |
| 2 | Invalid options or operands (ncurses clear normally uses 1) |

Diagnostics use Bash's builtin format. `-V`/`--version` identifies bashclear,
not the host ncurses version. Bash's output helper flushes and checks writes;
failures such as `/dev/full` and closed stdout return 1 and leave later shell
output usable. Some ncurses versions report success on these output errors.
Normal shell signal behavior, including `SIGPIPE`, still applies.

## Selecting and testing

Either name can be selected alone, with no companion builtin or extra library:

```sh
JOBS=2 ./build.sh --include clear --static --name small
JOBS=2 ./build.sh --include bashclear,clear --name clear-check
python3 tests/clear-check.py out/bash-clear-check
```

Dynamic packages use the same implementation. Build against a dynamic Bash
tree, then request `bashclear` and/or `clear` from `build-packages.sh`; each
package can be loaded independently with `enable -f`.

`tests/clear-check.py` captures expected bytes for every supported name,
compares available host ncurses entries, exercises private PTYs, and checks
options, errors, repeated calls, input ownership, and shell output recovery.
It never clears the caller's terminal. `--load-dir DIR` runs the same checks
with independently packaged `bashclear.so` and `clear.so` in a dynamic shell.
