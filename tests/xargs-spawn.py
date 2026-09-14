#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check xargs parsing, child execution, statuses, signals, and shell isolation.

Usage: python3 tests/xargs-spawn.py [BINARY]
Builds a small private helper with CC (default cc). No dynamic loadable or
external xargs implementation is required. Parallel output uses complete
records so normal child scheduling does not affect comparisons.
"""

import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile


HELPER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "status")) return argc > 2 ? atoi(argv[2]) : 0;
    if (!strcmp(argv[1], "signal")) { raise(SIGTERM); return 2; }
    if (!strcmp(argv[1], "notify")) {
        struct sigaction action;
        if (kill(getppid(), SIGUSR1) || sigaction(SIGUSR2, NULL, &action)) return 2;
        puts(action.sa_handler == SIG_IGN ? "ignored" : "default");
        return 0;
    }
    if (!strcmp(argv[1], "notify-parent")) {
        sigset_t mask;
        if (argc < 4 || sigprocmask(SIG_SETMASK, NULL, &mask) ||
            kill(getppid(), SIGQUIT)) return 2;
        if (!strcmp(argv[2], "blocked") && kill(getppid(), SIGUSR2)) return 2;
        printf("child:%d:%d:%d\n", sigismember(&mask, SIGQUIT),
               sigismember(&mask, SIGCHLD), sigismember(&mask, SIGUSR2));
        return atoi(argv[3]);
    }
    if (!strcmp(argv[1], "mask-pending")) {
        sigset_t mask, pending;
        if (sigprocmask(SIG_SETMASK, NULL, &mask) || sigpending(&pending)) return 2;
        printf("QUIT:%d:%d\nCHLD:%d:%d\nUSR2:%d:%d\n",
               sigismember(&mask, SIGQUIT), sigismember(&pending, SIGQUIT),
               sigismember(&mask, SIGCHLD), sigismember(&pending, SIGCHLD),
               sigismember(&mask, SIGUSR2), sigismember(&pending, SIGUSR2));
        return ferror(stdout) != 0;
    }
    if (!strcmp(argv[1], "environment")) {
        const char *value = getenv("XARGS_TEST_ENV");
        puts(value ? value : "<unset>");
    } else if (!strcmp(argv[1], "environment-values")) {
        for (int i = 2; i < argc && strcmp(argv[i], "--"); i++) {
            const char *value = getenv(argv[i]);
            puts(value ? value : "<unset>");
        }
    } else if (!strcmp(argv[1], "fd")) {
        puts(fcntl(7, F_GETFD) >= 0 ? "open" : "closed");
    } else if (!strcmp(argv[1], "signals")) {
        sigset_t mask;
        if (sigprocmask(SIG_SETMASK, NULL, &mask)) return 2;
        for (int i = 2; i < argc; i++) {
            int sig = atoi(argv[i]);
            struct sigaction action;
            if (sigaction(sig, NULL, &action)) return 2;
            printf("%d:%c:%d\n", sig,
                   action.sa_handler == SIG_DFL ? 'D' :
                   action.sa_handler == SIG_IGN ? 'I' : 'H',
                   sigismember(&mask, sig));
        }
    } else {
        if (!strcmp(argv[1], "batch")) printf("batch:%d\n", argc - 2);
        for (int i = 2; i < argc; i++) {
            const unsigned char *p = (const unsigned char *)argv[i];
            while (*p) printf("%02x", *p++);
            putchar('\n');
        }
    }
    return ferror(stdout) != 0;
}
"""


class Checks:
    def __init__(self, binary, root):
        self.binary, self.root, self.count = str(binary), root, 0
        self.env = {**os.environ, "PATH": "", "LC_ALL": "C"}
        self.env.pop("BASH_ENV", None)

    def run(self, script, *args, data=b"", setup=None, env=None):
        result = subprocess.run(
            [self.binary, "--noprofile", "--norc", "-c", script,
             "xargs-spawn", *map(str, args)], input=data, capture_output=True,
            cwd=self.root, env=self.env if env is None else env,
            preexec_fn=setup, timeout=20)
        assert b"AddressSanitizer" not in result.stderr, result.stderr
        assert b"runtime error:" not in result.stderr, result.stderr
        return result

    def check(self, script, *args, data=b"", output=b"", status=0,
              unordered=False, setup=None, env=None):
        result = self.run(script, *args, data=data, setup=setup, env=env)
        actual = result.stdout
        if unordered:
            actual, output = sorted(actual.splitlines()), sorted(output.splitlines())
        assert (result.returncode, actual) == (status, output), (
            script, args, result.returncode, status, actual, output, result.stderr)
        self.count += 1


def parser_checks(checks, helper, root):
    def batches(arguments, limit):
        return b"".join(
            f"batch:{len(arguments[start:start + limit])}\n".encode() +
            b"".join(arg.hex().encode() + b"\n"
                     for arg in arguments[start:start + limit])
            for start in range(0, len(arguments), limit))

    # Check both argv contents and invocation boundaries across small and
    # larger batches, including a final incomplete batch.
    words = [f"word-{i}".encode() for i in range(159)]
    for limit in (63, 64, 65, 129):
        checks.check('xargs -n "$1" "$2" batch', limit, helper,
                     data=b" ".join(words), output=batches(words, limit))
    varied = [b"a", b"b" * 65, b"c" * 1025, b"d", b"e" * 9000, b"last"] * 3
    checks.check('xargs -n 3 "$1" batch', helper,
                 data=b" ".join(varied), output=batches(varied, 3))

    quoted = [b"one", b"two words", b"three words", b"four five", b"", b"tail"]
    checks.check('xargs -n 2 "$1" batch', helper,
                 data=b'one \'two words\' "three words" four\\ five \'\' tail',
                 output=batches(quoted, 2))
    raw = [b"", b"two words", b'quote"slash\\', b"line\nbreak", b"last"]
    checks.check('xargs -0 -n 2 "$1" batch', helper,
                 data=b"\0".join(raw), output=batches(raw, 2))
    lines = [b"one two", b"three", b"four five"]
    checks.check('xargs -L 2 "$1" batch', helper,
                 data=b"\n\none two\n\nthree\nfour five",
                 output=batches(lines, 2))
    replacements = [b"prefix:one two:one two", b"prefix:three:three"]
    checks.check('xargs -I {} "$1" batch "prefix:{}:{}"', helper,
                 data=b"\none two\n\nthree\n", output=batches(replacements, 1))

    # -s includes the executable and fixed argument, each with its NUL.
    sized = [f"item{i:02d}".encode() for i in range(8)]
    size = len(os.fsencode(helper)) + 1 + len(b"batch") + 1 + 3 * 7
    checks.check('xargs -s "$1" "$2" batch', size, helper,
                 data=b" ".join(sized), output=batches(sized, 3))
    checks.check('xargs "$1" batch', helper, data=b"first second 'unfinished",
                 output=batches([b"first", b"second"], 2), status=1)

    # A fatal child stops after the already-read lookahead argument. A second
    # invocation must see the remaining FILE input, without reopening it.
    tail = [b"third", b"fourth", b"fifth"]
    for separator, flag in ((b" ", ""), (b"\0", "-0")):
        fixture = root / "fatal-input"
        fixture.write_bytes(separator.join([b"first", b"second", *tail]))
        checks.check('exec < "$2"; xargs ' + flag + ' -n 1 "$1" status 255; '
                     'printf "status:%s\\n" "$?"; xargs ' + flag + ' "$1" batch',
                     helper, fixture, output=b"status:124\n" + batches(tail, 3))


def argv_size_checks(checks, helper):
    def check(words):
        expected = f"batch:{len(words)}\n".encode()
        expected += b"".join(word.hex().encode() + b"\n" for word in words)
        checks.check('xargs -0 -n "$1" "$2" batch', len(words), helper,
                     data=b"\0".join(words) + b"\0", output=expected,
                     env={"PATH": "", "LC_ALL": "C", "TZ": "UTC", "TERM": "dumb"})

    # Include argv[0] and the helper mode in the complete vector size.
    for entries in (16, 17):
        check([f"word-{i}".encode() for i in range(entries - 2)])
    fixed = len(os.fsencode(helper)) + 1 + len(b"batch") + 1
    assert fixed < 512, "helper path too long for the 512-byte argv case"
    for total_bytes in (512, 513):
        check([b"v" * (total_bytes - fixed - 1)])


def environment_checks(checks, helper, root):
    # Keep the small case independent of the invoking developer/CI environment.
    # Larger environments exercise the same externally visible requirements.
    base_env = {"PATH": "", "LC_ALL": "C", "TZ": "UTC", "TERM": "dumb"}
    values = [
        {"XARGS_SMALL": "two words = value", "XARGS_EMPTY": ""},
        {f"XARG_{i}": f"v{i}" for i in range(24)},
        {"XARGS_LARGE": "ordinary value " * 160, "XARGS_TAIL": "last"},
    ]
    for exports in values:
        expected = b"".join(value.encode() + b"\n" for value in exports.values())
        checks.check('xargs -n 1 "$@"', helper, "environment-values", *exports, "--",
                     data=b"one\ntwo\n", output=expected * 2,
                     env={**base_env, **exports})

    fixture = root / "environment-input"
    fixture.write_bytes(b"one\ntwo\n")
    checks.check('export XARGS_TEST_ENV=first; '
                 'xargs -n 1 "$1" environment < "$2" || exit; '
                 'export XARGS_TEST_ENV="second value"; '
                 'xargs -n 1 "$1" environment < "$2" || exit; '
                 'unset XARGS_TEST_ENV; '
                 'xargs -n 1 "$1" environment < "$2"', helper, fixture,
                 output=b"first\n" * 2 + b"second value\n" * 2 + b"<unset>\n" * 2,
                 env=base_env)


def parent_signal_checks(checks, helper, root):
    fixture = root / "signal-input"
    fixture.write_bytes(b"one\ntwo\n")
    clean = b"QUIT:0:0\nCHLD:0:0\nUSR2:0:0\n"
    def setup():
        signal.pthread_sigmask(signal.SIG_UNBLOCK,
                               {signal.SIGQUIT, signal.SIGCHLD, signal.SIGUSR2})
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    # Exec preserves the shell process's mask and pending set; a forked
    # observer would lose the pending set. SIGQUIT is normally ignored by
    # this noninteractive shell, and must stay harmless after each command.
    for child_status, result, children in ((0, 0, 2), (255, 124, 1)):
        checks.check('xargs -n 1 "$1" notify-parent ordinary "$3" < "$2"; '
                     'printf "status:%s\\n" "$?"; '
                     'xargs -n 1 "$1" notify-parent ordinary 0 < "$2" || exit; '
                     'exec "$1" mask-pending', helper, fixture, child_status,
                     setup=setup,
                     output=b"child:0:0:0\n" * children +
                     f"status:{result}\n".encode() + b"child:0:0:0\n" * 2 + clean)

    def blocked():
        setup()
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        signal.signal(signal.SIGUSR2, signal.SIG_IGN)

    # The first invocation leaves USR2 pending under the inherited block;
    # the second must preserve it while restoring its own temporary mask.
    checks.check('xargs -n 1 "$1" notify-parent blocked 0 < "$2" || exit; '
                 'xargs -n 1 "$1" notify-parent blocked 0 < "$2" || exit; '
                 'exec "$1" mask-pending', helper, fixture, setup=blocked,
                 output=b"child:0:0:1\n" * 4 +
                 b"QUIT:0:0\nCHLD:0:0\nUSR2:1:1\n")
    checks.check('xargs -n 2 "$1" notify-parent ordinary 0; '
                 'printf "status:%s\\n" "$?"; exec "$1" mask-pending', helper,
                 data=b"one two three 'unfinished", setup=setup,
                 output=b"child:0:0:0\n" * 2 + b"status:1\n" + clean)


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "out/bash").resolve()
    with tempfile.TemporaryDirectory(prefix="xargs-spawn-") as directory:
        root = Path(directory)
        helper = root / "child-state"
        source = helper.with_suffix(".c")
        source.write_text(HELPER)
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                       ["-O2", "-Wall", "-Wextra", "-Werror", str(source),
                        "-o", str(helper)], check=True, capture_output=True)
        checks = Checks(binary, root)
        parser_checks(checks, helper, root)
        argv_size_checks(checks, helper)
        environment_checks(checks, helper, root)
        parent_signal_checks(checks, helper, root)
        plain = root / "plain"
        plain.write_text('/bin/printf "plain:<%s>\\n" "$@"\n')
        plain.chmod(0o755)
        denied = root / "denied"
        denied.write_text("ordinary nonexecutable file\n")
        denied.chmod(0o644)
        shadow = root / "printf"
        shadow.write_text('#!/bin/sh\nprintf "external:<%s>\\n" "$@"\n')
        shadow.chmod(0o755)

        arguments = [b"two words", b"*", b"literal ; $ ( )", b"", b"last"]
        payload = b"\0".join(arguments) + b"\0"
        encoded = b"".join(arg.hex().encode() + b"\n" for arg in arguments)
        signals = [signal.SIGINT, signal.SIGQUIT, signal.SIGCHLD,
                   signal.SIGPIPE, signal.SIGUSR1, signal.SIGUSR2]
        if hasattr(signal, "SIGRTMIN"):
            signals.append(signal.SIGRTMIN + 3)

        for parallel in (1, 2, 4):
            checks.check('xargs -0 -n 1 -P "$1" "$2" args', parallel, helper,
                         data=payload, output=encoded, unordered=parallel > 1)
            checks.check('PATH="$2"; xargs -0 -n 1 -P "$1" printf "<%s>\\n"',
                         parallel, root, data=payload,
                         output=b"".join(b"<" + arg + b">\n" for arg in arguments),
                         unordered=True)
            checks.check('xargs -n 1 -P "$1" "$2"', parallel, plain,
                         data=b"one\ntwo\n", output=b"plain:<one>\nplain:<two>\n",
                         unordered=True)
            for child_status, status in ((0, 0), (1, 123), (125, 123),
                                         (126, 126), (127, 127), (255, 124)):
                checks.check('xargs -n 1 -P "$1" "$2" status "$3"',
                             parallel, helper, child_status, data=b"one\n", status=status)
            checks.check('xargs -P "$1" "$2" signal', parallel, helper,
                         data=b"one\n", status=125)
            for command, status in ((denied, 126), (root / "missing", 127)):
                checks.check('xargs -P "$1" "$2"', parallel, command,
                             data=b"one\n", status=status)
            checks.check('xargs -n 1 -P "$1" "$2" status', parallel, helper,
                         data=b"0\n1\n0\n", status=123)
            checks.check('XARGS_TEST_ENV="temporary value" xargs -P "$1" "$2" environment',
                         parallel, helper, data=b"one\n", output=b"temporary value\n")
            checks.check('exec 7</dev/null; xargs -P "$1" "$2" fd', parallel, helper,
                         data=b"one\n", output=b"open\n")

            for prefix, ignored in (("", set()), ("set -m; ", set()),
                                    ("trap ':' USR1 PIPE; ", set()),
                                    ("trap '' USR1 PIPE; ", {signal.SIGUSR1, signal.SIGPIPE}),
                                    ("trap ':' INT QUIT CHLD; ", set()),
                                    ("trap '' INT QUIT CHLD; ",
                                     {signal.SIGINT, signal.SIGQUIT, signal.SIGCHLD})):
                expected = "".join(f"{sig}:{'I' if sig in ignored else 'D'}:0\n"
                                   for sig in signals).encode()
                checks.check(prefix + 'parallel=$1; helper=$2; shift 2; '
                             'xargs -P "$parallel" -I {} "$helper" signals "$@"',
                             parallel, helper, *signals, data=b"one\n", output=expected)

        # An inherited mask is retained by serial xargs children. The shell
        # must also regain that mask after xargs restores its SIGCHLD guard.
        blocked = {signal.SIGUSR2}
        ignored = signals[-1]
        def setup():
            signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
            signal.signal(ignored, signal.SIG_IGN)
        expected = "".join(f"{sig}:{'I' if sig == ignored else 'D'}:"
                           f"{int(sig in blocked)}\n" for sig in signals).encode()
        checks.check('helper=$1; shift; xargs "$helper" signals "$@"; "$helper" signals "$@"',
                     helper, *signals, output=expected * 2, setup=setup)

        checks.check('PATH="$1"; enable -n printf; xargs printf marker', root,
                     data=b"word\n", output=b"external:<marker>\nexternal:<word>\n")
        checks.check('xargs "$1" marker', shadow, data=b"word\n",
                     output=b"external:<marker>\nexternal:<word>\n")
        checks.check('PATH="$1"; xargs plain', root, data=b"word\n",
                     output=b"plain:<word>\n")
        checks.check('xargs -r /bin/echo', output=b"")
        checks.check('xargs /bin/echo', output=b"\n")
        checks.check('xargs exit; printf "parent-alive\\n"', data=b"0\n",
                     output=b"parent-alive\n")
        checks.check('trap \'printf "parent-exit\\n"\' EXIT; xargs /bin/echo',
                     data=b"word\n", output=b"word\nparent-exit\n")
        checks.check('trap \'trap "" USR2; printf "trap-delivered\\n"\' USR1; '
                     'xargs -n 1 "$1" notify; "$1" signals "$2"', helper, signal.SIGUSR2,
                     data=b"one\ntwo\nthree\n", output=b"default\n" * 3 +
                     f"trap-delivered\n{signal.SIGUSR2}:I:0\n".encode())
        checks.check('/bin/sh -c "exit 23" & background=$!; '
                     'xargs -n 1 /bin/echo; wait "$background"; printf "job:%s\\n" "$?"',
                     data=b"one\ntwo\n", output=b"one\ntwo\njob:23\n")
        fixture = root / "input"
        fixture.write_bytes(b"one two\n")
        checks.check('xargs /bin/echo < "$1"; xargs /bin/echo < "$1"', fixture,
                     output=b"one two\none two\n")
        print(f"xargs-spawn: {checks.count} checks passed")


if __name__ == "__main__":
    main()
