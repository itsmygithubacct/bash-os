#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only independent controls and trace assertions for strace."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

MARKER = b"STRACE-MARK\n"
ASSEMBLY = '.globl _start\n_start:\n    mov $1, %rax\n    mov $1, %rdi\n    lea msg(%rip), %rsi\n    mov $12, %rdx\n    syscall\n    cmp $12, %rax\n    jne bad\n    mov $257, %rax\n    mov $-100, %rdi\n    lea path(%rip), %rsi\n    xor %rdx, %rdx\n    xor %r10, %r10\n    syscall\n    cmp $-2, %rax\n    jne bad\n    mov $231, %rax\n    mov $42, %rdi\n    syscall\nbad:\n    mov $231, %rax\n    mov $98, %rdi\n    syscall\n.section .rodata\nmsg:\n    .ascii "STRACE-MARK\\n"\n    .byte 0\npath:\n    .ascii "missing-strace-path"\n    .byte 0\n'
CONTROL = '#define _GNU_SOURCE\n#include <errno.h>\n#include <signal.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <sys/ptrace.h>\n#include <sys/syscall.h>\n#include <sys/types.h>\n#include <sys/user.h>\n#include <sys/wait.h>\n#include <unistd.h>\n\nstatic int collect(pid_t pid, int *status) {\n    pid_t got;\n    do got = waitpid(pid, status, 0); while (got < 0 && errno == EINTR);\n    return got == pid;\n}\nint main(void) {\n    pid_t pid = fork();\n    if (pid < 0) { perror("fork"); return 98; }\n    if (pid == 0) {\n        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("PTRACE_TRACEME"); _exit(97); }\n        raise(SIGSTOP);\n        execl("./tracee-core", "./tracee-core", (char *)0);\n        perror("execl tracee-core"); _exit(96);\n    }\n    int status, entering = 1, calls[4] = {0}, errors[4] = {0};\n    long numbers[4] = {SYS_execve, SYS_write, SYS_openat, SYS_exit_group};\n    if (!collect(pid, &status)) { perror("initial waitpid"); goto failed; }\n    if (WIFEXITED(status) || WIFSIGNALED(status)) {\n        fprintf(stderr, "child terminated before initial stop: status=%#x\\n", status); return 98;\n    }\n    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {\n        fprintf(stderr, "unexpected initial status=%#x\\n", status); goto failed;\n    }\n    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {\n        perror("PTRACE_SETOPTIONS"); goto failed;\n    }\n    for (;;) {\n        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) { perror("PTRACE_SYSCALL"); goto failed; }\n        if (!collect(pid, &status)) { perror("trace waitpid"); goto failed; }\n        if (WIFEXITED(status)) {\n            int bad = WEXITSTATUS(status) != 42;\n            for (int i = 0; i < 4; i++)\n                if (calls[i] != 1 || errors[i] != (i == 2)) bad = 1;\n            if (bad) {\n                fprintf(stderr, "native mismatch: exit=%d execve=%d/%d write=%d/%d openat=%d/%d exit_group=%d/%d\\n",\n                        WEXITSTATUS(status), calls[0], errors[0], calls[1], errors[1],\n                        calls[2], errors[2], calls[3], errors[3]); return 98;\n            }\n            fprintf(stderr, "native-ptrace-ok: execve=1/0 write=1/0 openat=1/1 exit_group=1/0\\n");\n            return 0;\n        }\n        if (WIFSIGNALED(status)) { fprintf(stderr, "native child signal=%d\\n", WTERMSIG(status)); return 98; }\n        if (!WIFSTOPPED(status)) { fprintf(stderr, "unexpected trace status=%#x\\n", status); goto failed; }\n        if (WSTOPSIG(status) == SIGTRAP) continue; /* exec transition */\n        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {\n            fprintf(stderr, "unexpected stop signal=%d\\n", WSTOPSIG(status)); goto failed;\n        }\n        struct user_regs_struct regs;\n        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) { perror("PTRACE_GETREGS"); goto failed; }\n        int index = -1;\n        for (int i = 0; i < 4; i++) if ((long)regs.orig_rax == numbers[i]) index = i;\n        if (index < 0) { fprintf(stderr, "unexpected syscall=%ld\\n", (long)regs.orig_rax); goto failed; }\n        if (entering) calls[index]++;\n        else {\n            long value = (long)regs.rax;\n            if (value < 0 && value >= -4095) errors[index]++;\n            if ((index == 0 && value != 0) || (index == 1 && value != 12) ||\n                (index == 2 && value != -ENOENT)) {\n                fprintf(stderr, "unexpected syscall return: nr=%ld result=%ld\\n", (long)regs.orig_rax, value); goto failed;\n            }\n        }\n        entering = !entering;\n    }\nfailed:\n    fprintf(stderr, "native control failed; cleaning up owned child\\n");\n    kill(pid, SIGKILL);\n    collect(pid, &status);\n    return 98;\n}\n'

EXPECTED = ['execve', 'write', 'openat', 'exit_group']
PREFIX = r'(?:\[pid\s+\d+\]\s+|\d+\s+)?'
CALL_START = re.compile(PREFIX + r'([a-z_][a-z_0-9]*)\(')
BANNER = re.compile(PREFIX + r'\+\+\+ (?:exited with 42|exec) \+\+\+\Z')
UUID = re.compile(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z')
ATOM = re.compile(r'(?:[A-Za-z_][A-Za-z_0-9]*|-?(?:0x[0-9a-fA-F]+|[0-9]+))(?:\|(?:[A-Za-z_][A-Za-z_0-9]*|0x[0-9a-fA-F]+|[0-9]+))*\Z')
RESULT = re.compile(r'\s+=\s+(?:\?|-1(?:\s+errno=[0-9]+|\s+[A-Z][A-Z_0-9]*(?:\s+\([A-Za-z0-9 .:/_-]+\))?)?|-?[0-9]+|0x[0-9a-fA-F]+)\s*\Z')
POINTER = re.compile(r'(?:NULL|0x[0-9a-fA-F]+|-?[0-9]+)\Z')


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or
            os.environ.get('HOME') != '/tmp/parity-home' or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            not UUID.fullmatch(marker) or os.uname().machine != 'x86_64'):
        raise ValueError('requires the isolated uid-2000 x86_64 parity guest')


def records(data):
    if len(data) > 1024 * 1024:
        raise ValueError('trace exceeds size limit')
    text = data.decode('utf-8', errors='strict')
    if not text or not text.endswith('\n'):
        raise ValueError('empty or unterminated trace')
    result = []
    for line in text.splitlines():
        if len(line) > 8192:
            raise ValueError('trace line exceeds size limit')
        if BANNER.fullmatch(line):
            continue
        m = CALL_START.match(line)
        if not m:
            raise ValueError('unexpected trace line: ' + line)
        args = []
        i = m.end()
        while True:
            while i < len(line) and line[i] == ' ':
                i += 1
            start = i
            if i < len(line) and line[i] == '"':
                i += 1
                while i < len(line) and line[i] != '"':
                    if line[i] == '\\':
                        i += 1
                        if i >= len(line) or line[i] not in 'nrt\\"x':
                            raise ValueError('invalid quoted escape')
                        if line[i] == 'x':
                            if not re.fullmatch(r'[0-9a-fA-F]{2}', line[i + 1:i + 3]):
                                raise ValueError('invalid hexadecimal escape')
                            i += 2
                    elif not 32 <= ord(line[i]) < 127:
                        raise ValueError('invalid quoted character')
                    i += 1
                if i >= len(line):
                    raise ValueError('unterminated string')
                i += 1
            else:
                while i < len(line) and line[i] not in ',) ':
                    i += 1
                if not ATOM.fullmatch(line[start:i]):
                    raise ValueError('invalid argument')
            args.append(line[start:i])
            while i < len(line) and line[i] == ' ':
                i += 1
            if i >= len(line):
                raise ValueError('unterminated arguments')
            if line[i] == ')':
                i += 1
                break
            if line[i] != ',':
                raise ValueError('invalid argument separator')
            i += 1
            if len(args) >= 6:
                raise ValueError('too many arguments')
        if not RESULT.fullmatch(line[i:]):
            raise ValueError('invalid or missing result tail')
        tail = line[i:].split('=', 1)[1].strip()
        if (tail == '?') != (m.group(1) in ('exit', 'exit_group')):
            raise ValueError('invalid non-returning syscall result')
        result.append((m.group(1), args))
        if len(result) > 64:
            raise ValueError('too many trace records')
    return result


def require_names(data, names):
    seen = [name for name, _ in records(data)]
    if seen != names:
        raise ValueError('syscall sequence: expected %r, observed %r' % (names, seen))


def require_decode(data):
    rows = records(data)
    if [name for name, _ in rows] != EXPECTED:
        raise ValueError('decoded trace lacks the expected ordered calls')
    args = dict(rows)
    if (len(args['execve']) != 3 or args['execve'][0] != '"./tracee-core"' or
            not all(POINTER.fullmatch(value) for value in args['execve'][1:])):
        raise ValueError('incorrect execve arguments')
    if args['write'] != ['1', '"STRACE-MARK\\n"', '12']:
        raise ValueError('incorrect write arguments')
    opened = args['openat']
    if (len(opened) not in (3, 4) or
            opened[:3] != ['AT_FDCWD', '"missing-strace-path"', 'O_RDONLY'] or
            (len(opened) == 4 and not re.fullmatch(r'(?:0+|0x0+)', opened[3]))):
        raise ValueError('incorrect openat arguments')
    if args['exit_group'] != ['42']:
        raise ValueError('incorrect exit_group arguments')


def setup(home):
    # Parser controls are guest-only and must reject duplicate, hidden, extra,
    # missing, malformed and unterminated records before candidate assertions.
    good = (b'[pid 123] execve("./tracee-core", 0x1, 0x2) = 0\n'
            b'[pid 123] write(1, "STRACE-MARK\\n", 12) = 12\n'
            b'[pid 123] openat(AT_FDCWD, "missing-strace-path", O_RDONLY) = -1 errno=2\n'
            b'[pid 123] exit_group(42) = ?\n[pid 123] +++ exited with 42 +++\n')
    require_names(good, EXPECTED)
    require_decode(good)
    mode_line = good.replace(b'O_RDONLY)', b'O_RDONLY, 00)')
    require_names(mode_line, EXPECTED)
    require_decode(mode_line)
    quoted = good.replace(b'"STRACE-MARK\\n"', b'"getpid() and \\\"read(0)\\\""')
    require_names(quoted, EXPECTED)
    negatives = [b'', good.rstrip(b'\n'), good + b'write(1, 0, 1) = 1\n',
                 good.replace(b'write(', b'unknown(', 1),
                 good.replace(b'exit_group(42) = ?\n', b''),
                 good.replace(b' = 12\n', b' = 12 read(0, 0, 1) = 1\n'),
                 good.replace(b'"STRACE-MARK\\n"', b'read(0, 0, 1)'),
                 good.replace(b'"STRACE-MARK\\n"', b'getpid()'),
                 good.replace(b'"STRACE-MARK\\n"', b'unknown_call(0)'),
                 good.replace(b' = 12\n', b'\n'),
                 good.replace(b' = 12\n', b' = nonsense\n'),
                 good.replace(b' = 12\n', b' = 12 junk\n'),
                 good.replace(b' = 12\n', b' = 12 errno=2\n'),
                 good.replace(b' = 12\n', b' = ?\n'),
                 good.replace(b'exit_group(42) = ?', b'exit_group(42) = 42'),
                 good.replace(b' = 12\n', b' = 12 read(0)\n'),
                 good.replace(b'"STRACE-MARK\\n"', b'"unterminated'),
                 good.replace(b', 12)', b',)'),
                 good.replace(b'write(', b'write(' + b'1' * 8193, 1),
                 good + b'error: tracing failed\n']
    for bad in negatives:
        try:
            require_names(bad, EXPECTED)
        except (ValueError, UnicodeError):
            continue
        raise ValueError('trace parser accepted invalid control')
    decode_negatives = [good.replace(b'"STRACE-MARK\\n"', b'0x1234'),
                        good.replace(b'AT_FDCWD', b'-100'),
                        good.replace(b'O_RDONLY', b'0'),
                        good.replace(b'"./tracee-core"', b'0x5678'),
                        good.replace(b'exit_group(42)', b'exit_group(0)'),
                        good.replace(b'0x1, 0x2', b'0x1'),
                        good.replace(b'0x1, 0x2', b''),
                        good.replace(b'O_RDONLY)', b'O_RDONLY, garbage)'),
                        good.replace(b'O_RDONLY)', b'O_RDONLY, 07)'),
                        good.replace(b'O_RDONLY)', b'O_RDONLY, 00, 0)')]
    for bad in decode_negatives:
        try:
            require_decode(bad)
        except (ValueError, UnicodeError):
            continue
        raise ValueError('decode parser accepted invalid control')
    (home / 'parser-controls.json').write_text(json.dumps({
        'positive': 3, 'negative': len(negatives),
        'decode_negative': len(decode_negatives)}) + '\n')
    Path('tracee-core.s').write_text(ASSEMBLY)
    Path('native-trace.c').write_text(CONTROL)
    with (home / 'gcc.out').open('wb') as out, (home / 'gcc.err').open('wb') as err:
        commands = [
            ['/usr/bin/gcc', '-static', '-nostdlib', '-no-pie', '-o', 'tracee-core', 'tracee-core.s'],
            ['/usr/bin/gcc', '-O0', '-Wall', '-Wextra', '-o', 'native-trace', 'native-trace.c'],
        ]
        for cmd in commands:
            subprocess.run(cmd, stdout=out, stderr=err, check=True, timeout=15)
    for name, command, expected in [('direct', './tracee-core', 42), ('ptrace', './native-trace', 0)]:
        result = subprocess.run([command], capture_output=True, timeout=10)
        (home / (name + '.out')).write_bytes(result.stdout)
        (home / (name + '.err')).write_bytes(result.stderr)
        (home / (name + '.status')).write_text(str(result.returncode) + '\n')
        if result.returncode != expected or result.stdout != MARKER or (name == 'direct' and result.stderr):
            raise ValueError(name + ' independent control failed')
        if name == 'ptrace' and not result.stderr.startswith(b'native-ptrace-ok:'):
            raise ValueError('native ptrace control lacks success record')
    if Path('missing-strace-path').exists() or Path('missing-strace-path').is_symlink():
        raise ValueError('control unexpectedly created the missing path')


def verify(home, mode):
    modes = {'exec-lines', 'exec-decode', 'exec-status', 'output-route',
             'output-stdout', 'output-status', 'filter-names',
             'filter-numbers', 'filter-exclude'}
    if mode not in modes:
        raise ValueError('unknown requirement mode')
    observations = {'requirement': mode, 'checks': {}, 'read_errors': {}}

    def read(name, path):
        try:
            return path.read_bytes()
        except OSError as error:
            observations['read_errors'][name] = str(error)
            return None

    out = read('stdout', home / 'candidate.out')
    err = read('stderr', home / 'candidate.err')
    raw_status = read('status', home / 'candidate.status')
    status = None
    if raw_status is not None and re.fullmatch(rb'[0-9]+\n', raw_status):
        status = int(raw_status.strip())
    routed = mode.startswith('output-')
    if routed:
        trace = read('route_file', Path('route.trace'))
        if trace is not None:
            (home / 'candidate.trace').write_bytes(trace)
    else:
        trace = err
    expected_names = ['write', 'openat'] if mode.startswith('filter-') else EXPECTED
    observations.update(status=status, stdout_hex=out.hex() if out is not None else None,
                        stderr_bytes=len(err) if err is not None else None,
                        trace_bytes=len(trace) if trace is not None else None,
                        destination='route.trace' if routed else 'stderr')

    def check(name, assertion):
        try:
            assertion()
            observations['checks'][name] = {'ok': True}
        except (ValueError, UnicodeError) as error:
            observations['checks'][name] = {'ok': False, 'error': str(error)}

    def marker():
        if out != MARKER:
            raise ValueError('tracee stdout differs from direct control')

    def exit_status():
        if status != 42:
            raise ValueError('tracee status differs from direct control')

    def empty_stderr():
        if err != b'':
            raise ValueError('stderr is not empty with -o')

    def selected_trace():
        if trace is None:
            raise ValueError('trace destination is missing or unreadable')
        require_names(trace, expected_names)

    def decoded_trace():
        if trace is None:
            raise ValueError('trace destination is missing or unreadable')
        require_decode(trace)

    def routed_trace():
        # Check the two independently above as well, so neither failure hides
        # the other in the saved observations.
        empty_stderr()
        selected_trace()

    check('controlled_marker', marker)
    check('controlled_status', exit_status)
    check('selected_trace_destination', selected_trace)
    if routed:
        check('routing_stderr_empty', empty_stderr)
    target = {
        'exec-lines': selected_trace,
        'exec-decode': decoded_trace,
        'exec-status': exit_status,
        'output-route': routed_trace,
        'output-stdout': marker,
        'output-status': exit_status,
        'filter-names': selected_trace,
        'filter-numbers': selected_trace,
        'filter-exclude': selected_trace,
    }[mode]
    check('requirement', target)
    (home / 'assertions.json').write_text(json.dumps(observations, indent=2) + '\n')
    failures = [(name, result['error']) for name, result in observations['checks'].items()
                if not result['ok']]
    if failures:
        for name, error in failures:
            print(name + ': ' + error)
        return 1
    print(mode + '-ok')
    return 0


def main():
    require_guest()
    home = Path(os.environ['HOME'])
    if sys.argv[1:] == ['setup']:
        setup(home)
        return 0
    if len(sys.argv) == 2:
        return verify(home, sys.argv[1])
    raise ValueError('expected setup or requirement mode')


if __name__ == '__main__':
    raise SystemExit(main())
