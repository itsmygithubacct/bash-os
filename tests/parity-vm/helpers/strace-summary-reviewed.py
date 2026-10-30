#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only controls and semantic assertions for strace summary counts."""
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

EXPECTED = {"execve": (1, 0), "write": (1, 0), "openat": (1, 1), "exit_group": (1, 0)}
MARKER = b"STRACE-MARK\n"
ASSEMBLY = r'''.globl _start
_start:
    mov $1, %rax
    mov $1, %rdi
    lea msg(%rip), %rsi
    mov $12, %rdx
    syscall
    cmp $12, %rax
    jne bad
    mov $257, %rax
    mov $-100, %rdi
    lea path(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall
    cmp $-2, %rax
    jne bad
    mov $231, %rax
    mov $42, %rdi
    syscall
bad:
    mov $231, %rax
    mov $98, %rdi
    syscall
.section .rodata
msg:
    .ascii "STRACE-MARK\n"
    .byte 0
path:
    .ascii "missing-strace-path"
    .byte 0
'''

CONTROL = r'''#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static int collect(pid_t pid, int *status) {
    pid_t got;
    do got = waitpid(pid, status, 0); while (got < 0 && errno == EINTR);
    return got == pid;
}
int main(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 98; }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { perror("PTRACE_TRACEME"); _exit(97); }
        raise(SIGSTOP);
        execl("./tracee-core", "./tracee-core", (char *)0);
        perror("execl tracee-core"); _exit(96);
    }
    int status, entering = 1, calls[4] = {0}, errors[4] = {0};
    long numbers[4] = {SYS_execve, SYS_write, SYS_openat, SYS_exit_group};
    if (!collect(pid, &status)) { perror("initial waitpid"); goto failed; }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        fprintf(stderr, "child terminated before initial stop: status=%#x\n", status); return 98;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "unexpected initial status=%#x\n", status); goto failed;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0) {
        perror("PTRACE_SETOPTIONS"); goto failed;
    }
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) { perror("PTRACE_SYSCALL"); goto failed; }
        if (!collect(pid, &status)) { perror("trace waitpid"); goto failed; }
        if (WIFEXITED(status)) {
            int bad = WEXITSTATUS(status) != 42;
            for (int i = 0; i < 4; i++)
                if (calls[i] != 1 || errors[i] != (i == 2)) bad = 1;
            if (bad) {
                fprintf(stderr, "native mismatch: exit=%d execve=%d/%d write=%d/%d openat=%d/%d exit_group=%d/%d\n",
                        WEXITSTATUS(status), calls[0], errors[0], calls[1], errors[1],
                        calls[2], errors[2], calls[3], errors[3]); return 98;
            }
            fprintf(stderr, "native-ptrace-ok: execve=1/0 write=1/0 openat=1/1 exit_group=1/0\n");
            return 0;
        }
        if (WIFSIGNALED(status)) { fprintf(stderr, "native child signal=%d\n", WTERMSIG(status)); return 98; }
        if (!WIFSTOPPED(status)) { fprintf(stderr, "unexpected trace status=%#x\n", status); goto failed; }
        if (WSTOPSIG(status) == SIGTRAP) continue; /* exec transition */
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            fprintf(stderr, "unexpected stop signal=%d\n", WSTOPSIG(status)); goto failed;
        }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) { perror("PTRACE_GETREGS"); goto failed; }
        int index = -1;
        for (int i = 0; i < 4; i++) if ((long)regs.orig_rax == numbers[i]) index = i;
        if (index < 0) { fprintf(stderr, "unexpected syscall=%ld\n", (long)regs.orig_rax); goto failed; }
        if (entering) calls[index]++;
        else {
            long value = (long)regs.rax;
            if (value < 0 && value >= -4095) errors[index]++;
            if ((index == 0 && value != 0) || (index == 1 && value != 12) ||
                (index == 2 && value != -ENOENT)) {
                fprintf(stderr, "unexpected syscall return: nr=%ld result=%ld\n", (long)regs.orig_rax, value); goto failed;
            }
        }
        entering = !entering;
    }
failed:
    fprintf(stderr, "native control failed; cleaning up owned child\n");
    kill(pid, SIGKILL);
    collect(pid, &status);
    return 98;
}
'''


def require_guest():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    if (os.getuid() != 2000 or os.geteuid() != 2000 or
            Path.cwd() != Path('/tmp/parity-case') or
            os.environ.get('HOME') != '/tmp/parity-home' or
            Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU' or
            not re.fullmatch(r'[0-9a-fA-F-]{36}', marker) or os.uname().machine != 'x86_64'):
        raise ValueError('requires the isolated uid-2000 x86_64 parity guest')


def summary(text):
    """Read named count columns; tolerate timing columns and blank zero errors."""
    header = None
    header_line = None
    spans = None
    rows = {}
    total = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if set(line) <= {'-', ' '}:
            if header is None:
                raise ValueError('separator before header')
            proposed = [(m.start(), m.end()) for m in re.finditer(r'-+', raw)]
            labels = [re.sub(r'%\s+time', 'percent', header_line[a:b].strip()) for a, b in proposed]
            if labels != header:
                raise ValueError('separator does not identify header columns')
            spans = proposed
            continue
        if '(' in line:
            raise ValueError('per-call record in summary output')
        fields = re.sub(r'%\s+time', 'percent', line).split()
        if {'syscall', 'calls', 'errors'} <= set(fields):
            if header is not None or len(set(fields)) != len(fields):
                raise ValueError('duplicate summary header')
            if set(fields) - {'syscall', 'calls', 'errors', 'percent', 'seconds', 'usecs/call', 'usec/call'}:
                raise ValueError('unknown summary column')
            header = fields
            header_line = raw
            continue
        if header is None:
            raise ValueError('missing summary header')
        if spans:
            if raw[spans[-1][1]:].strip() or any(raw[b:a].strip() for (_, b), (a, _) in zip(spans, spans[1:])):
                raise ValueError('data outside summary columns')
            fields = [raw[a:b].strip() for a, b in spans]
            for i, value in enumerate(fields):
                if not value and header[i] == 'errors':
                    fields[i] = '0'
                elif not value:
                    raise ValueError('missing non-errors cell')
        if len(fields) != len(header):
            raise ValueError('malformed summary row')
        row = dict(zip(header, fields))
        if not re.fullmatch(r'[0-9]+', row['calls']) or not re.fullmatch(r'[0-9]+', row['errors']):
            raise ValueError('invalid count')
        for name in set(header) - {'syscall', 'calls', 'errors'}:
            value = float(row[name])
            if not math.isfinite(value) or value < 0:
                raise ValueError('invalid timing field')
        counts = (int(row['calls']), int(row['errors']))
        if row['syscall'] == 'total':
            if total is not None:
                raise ValueError('duplicate total row')
            total = counts
        elif row['syscall'] in rows:
            raise ValueError('duplicate syscall row')
        else:
            rows[row['syscall']] = counts
    if header is None or not rows:
        raise ValueError('empty summary')
    if total is not None and total != tuple(sum(v[i] for v in rows.values()) for i in [0, 1]):
        raise ValueError('inconsistent total row')
    return rows


def setup(home):
    plain = 'syscall calls errors\nexecve 1 0\nwrite 1 0\nopenat 1 1\nexit_group 1 0\n'
    widths = [6, 11, 11, 9, 9, 16]
    def aligned(values):
        return ' '.join(value.rjust(width) if i < 5 else value.ljust(width)
                        for i, (value, width) in enumerate(zip(values, widths))).rstrip() + '\n'
    timed_header = aligned(['% time', 'seconds', 'usecs/call', 'calls', 'errors', 'syscall'])
    timed_header += ' '.join('-' * width for width in widths) + '\n'
    timed = timed_header + ''.join(aligned(['25.00', '0.001', '1000', '1', '1' if name == 'openat' else '', name]) for name in EXPECTED)
    timed += aligned(['100.00', '0.004', '1000', '4', '1', 'total'])
    assert summary(plain) == summary(timed) == EXPECTED
    rejected = ['', plain + 'openat 1 0\n', 'write(1, buffer, 12) = 12\n', plain + 'bad row\n']
    rejected.append('% time seconds usecs/call calls errors syscall\n25 0.001 1 1 write\n')
    for missing in [0, 1, 2, 3, 5]:
        fields = ['25.00', '0.001', '1000', '1', '1', 'write']
        fields[missing] = ''
        rejected.append(timed_header + aligned(fields))
    for text in rejected:
        try:
            summary(text)
        except ValueError:
            continue
        raise ValueError('summary parser accepted an invalid control')
    (home / 'parser-controls.json').write_text(json.dumps({'positive': 2, 'negative': len(rejected), 'passed': True}) + '\n')
    Path('tracee-core.s').write_text(ASSEMBLY)
    Path('native-trace.c').write_text(CONTROL)
    with (home / 'gcc.out').open('wb') as out, (home / 'gcc.err').open('wb') as err:
        subprocess.run(['/usr/bin/gcc', '-static', '-nostdlib', '-no-pie', '-o', 'tracee-core', 'tracee-core.s'], stdout=out, stderr=err, check=True, timeout=15)
        subprocess.run(['/usr/bin/gcc', '-O0', '-Wall', '-Wextra', '-o', 'native-trace', 'native-trace.c'], stdout=out, stderr=err, check=True, timeout=15)
    for name, command, expected in [('direct', './tracee-core', 42), ('ptrace', './native-trace', 0)]:
        result = subprocess.run([command], capture_output=True, timeout=10)
        (home / (name + '.out')).write_bytes(result.stdout)
        (home / (name + '.err')).write_bytes(result.stderr)
        (home / (name + '.status')).write_text(str(result.returncode) + '\n')
        if result.returncode != expected or result.stdout != MARKER or (name == 'direct' and result.stderr):
            raise ValueError(name + ' independent control failed')
        if name == 'ptrace' and not result.stderr.startswith(b'native-ptrace-ok:'):
            raise ValueError('native ptrace control lacks success record')
    if Path('missing-strace-path').exists():
        raise ValueError('control unexpectedly created the missing path')


def verify(home, mode):
    observations = {}
    failures = []
    for option in ['c', 'summary']:
        try:
            status = int((home / (option + '.status')).read_text())
            output = (home / (option + '.out')).read_bytes()
            trace = (home / (option + '.trace')).read_text()
            if status != 42 or output != MARKER:
                raise ValueError('traced program status or output differs from the independent control')
            rows = summary(trace)
            observations[option] = rows
            if set(rows) != set(EXPECTED):
                raise ValueError('summary does not contain exactly the four known syscalls')
            if mode == 'r2' and any(rows[name][0] != EXPECTED[name][0] for name in EXPECTED):
                raise ValueError('incorrect syscall counts')
            if mode == 'r3' and any(rows[name][1] != EXPECTED[name][1] for name in EXPECTED):
                raise ValueError('incorrect syscall error counts')
        except (OSError, ValueError) as error:
            failures.append(option + ': ' + str(error))
    (home / 'assertions.json').write_text(json.dumps({'requirement': mode, 'observations': observations, 'failures': failures}, indent=2) + '\n')
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
    if len(sys.argv) == 2 and sys.argv[1] in {'r1', 'r2', 'r3'}:
        return verify(home, sys.argv[1])
    raise ValueError('expected setup or r1/r2/r3')


if __name__ == '__main__':
    raise SystemExit(main())
