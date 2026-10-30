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
CALL = re.compile(PREFIX + r'([a-z_][a-z_0-9]*)\((.*)\)(?:\s+=\s+([^\n]+))?\Z')
BANNER = re.compile(PREFIX + r'\+\+\+ (?:exited with 42|exec) \+\+\+\Z')
UUID = re.compile(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z')


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or
            os.environ.get('HOME') != '/tmp/parity-home' or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            not UUID.fullmatch(marker) or os.uname().machine != 'x86_64'):
        raise ValueError('requires the isolated uid-2000 x86_64 parity guest')


def records(data):
    text = data.decode('utf-8', errors='strict')
    if not text or not text.endswith('\n'):
        raise ValueError('empty or unterminated trace')
    result = []
    for line in text.splitlines():
        if BANNER.fullmatch(line):
            continue
        m = CALL.fullmatch(line)
        if (not m or re.search(r'\)\s*=.*\b[a-z_][a-z_0-9]*\(', line) or
                re.search(r'\b(?:execve|write|openat|exit_group|syscall_[0-9]+)\(', m.group(2))):
            raise ValueError('unexpected trace line: ' + line)
        result.append((m.group(1), m.group(2)))
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
    patterns = {
        'execve': r'^"\./tracee-core"\s*,',
        'write': r'^1\s*,\s*"STRACE-MARK\\n"\s*,\s*12\s*$',
        'openat': r'^AT_FDCWD\s*,\s*"missing-strace-path"\s*,\s*O_RDONLY(?:\s*,.*)?$',
        'exit_group': r'^42\s*$',
    }
    for name, pattern in patterns.items():
        if not re.search(pattern, args[name]):
            raise ValueError('incorrect symbolic arguments for ' + name + ': ' + args[name])


def setup(home):
    # Parser controls are guest-only and must reject duplicate, hidden, extra,
    # missing, malformed and unterminated records before candidate assertions.
    good = (b'[pid 123] execve("./tracee-core", 0x1, 0x2) = 0\n'
            b'[pid 123] write(1, "STRACE-MARK\\n", 12) = 12\n'
            b'[pid 123] openat(AT_FDCWD, "missing-strace-path", O_RDONLY) = -1 errno=2\n'
            b'[pid 123] exit_group(42) = ?\n[pid 123] +++ exited with 42 +++\n')
    require_names(good, EXPECTED)
    require_decode(good)
    negatives = [b'', good.rstrip(b'\n'), good + b'write(1, 0, 1) = 1\n',
                 good.replace(b'write(', b'unknown(', 1),
                 good.replace(b'exit_group(42) = ?\n', b''),
                 good.replace(b' = 12\n', b' = 12 read(0, 0, 1) = 1\n'),
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
                        good.replace(b'exit_group(42)', b'exit_group(0)')]
    for bad in decode_negatives:
        try:
            require_decode(bad)
        except (ValueError, UnicodeError):
            continue
        raise ValueError('decode parser accepted invalid control')
    (home / 'parser-controls.json').write_text(json.dumps({
        'positive': 1, 'negative': len(negatives),
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
    failures = []
    observations = {'requirement': mode}
    try:
        out = (home / 'candidate.out').read_bytes()
        err = (home / 'candidate.err').read_bytes()
        status_text = (home / 'candidate.status').read_text().strip()
        if not re.fullmatch(r'[0-9]+', status_text):
            raise ValueError('invalid captured candidate status')
        status = int(status_text)
        observations.update(status=status, stdout_hex=out.hex(), stderr_bytes=len(err))
        routed = mode.startswith('output-')
        if routed:
            path = Path('route.trace')
            trace = path.read_bytes() if path.is_file() else b''
            (home / 'candidate.trace').write_bytes(trace)
        else:
            trace = err
        if mode == 'exec-lines':
            if out != MARKER:
                raise ValueError('tracee stdout differs from direct control')
            require_names(trace, EXPECTED)
        elif mode == 'exec-decode':
            require_decode(trace)
        elif mode == 'exec-status':
            if status != 42:
                raise ValueError('tracee status not propagated')
        elif mode == 'output-route':
            if err:
                raise ValueError('stderr is not empty with -o')
            require_names(trace, EXPECTED)
        elif mode == 'output-stdout':
            if out != MARKER:
                raise ValueError('stdout differs from direct control with -o')
        elif mode == 'output-status':
            if status != 42:
                raise ValueError('tracee status not propagated with -o')
        elif mode in ('filter-names', 'filter-numbers', 'filter-exclude'):
            require_names(trace, ['write', 'openat'])
        else:
            raise ValueError('unknown requirement mode')
    except (OSError, ValueError, UnicodeError) as error:
        failures.append(str(error))
    observations['failures'] = failures
    (home / 'assertions.json').write_text(json.dumps(observations, indent=2) + '\n')
    if failures:
        print('\n'.join(failures))
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
