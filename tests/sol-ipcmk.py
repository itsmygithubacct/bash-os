#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real owned IPC checks. Requires a prebuilt test oracle; never compiles."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

KINDS = {
    'shm': ('-M 4097', 4097), 'sem': ('-S 3', 3), 'msg': ('-Q', 0),
    'posix-shm': ('-m 4097', 4097), 'posix-sem': ('-s', 0),
    'posix-msg': ('-q', 0),
}


def setup(oracle):
    return f'''enable -f {shlex.quote(str(Path(oracle).resolve()))} ipcmk_check || exit 90
PATH=
export LC_ALL=C
[[ $(type -t ipcmk) == builtin && $(type -t ipcctl) == builtin ]] || exit 91
umask 0
shopt -s nullglob
fds=(/proc/$$/fd/*); before=${{#fds[@]}}
'''


def cycle(kind, output, mode='600', collision=False):
    options, amount = KINDS[kind]
    posix = kind.startswith('posix-')
    out = shlex.quote(str(output))
    lines = []
    if posix:
        lines.append('name="/sol_ipcmk_${BASHPID}_' + kind + '"')
        options += ' -n "$name"'
    lines.append(f'ipcmk {options} -p {mode} >{out} || exit 10')
    if collision and posix:
        lines.append(f'if ipcmk {options} -p {mode} >{out}.collision 2>{out}.err; then exit 11; fi')
        lines.append(f'[[ ! -s {out}.collision ]] || exit 12')
    lines.append(f'ipcmk_check {kind} {out} {amount} {mode} || exit 13')
    return '\n'.join(lines) + '\n'


def run(binary, script, label):
    p = subprocess.run([str(Path(binary).resolve()), '--noprofile', '--norc', '-c', script], text=True, capture_output=True)
    print(f'{label}: exit={p.returncode}')
    if p.stdout: print(p.stdout, end='')
    if p.stderr: print(p.stderr, end='')
    if p.returncode: raise AssertionError(label)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary'); ap.add_argument('oracle')
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='sol-ipcmk-') as directory:
        out = Path(directory) / 'output'
        start = setup(a.oracle)
        for kind in KINDS:
            script = start
            for mode in ('600', '640', '644', '660', '700'):
                script += cycle(kind, out, mode, collision=True)
            script += 'for ((i=0;i<40;i++)); do\n' + cycle(kind, out) + 'done\n'
            options, amount = KINDS[kind]
            named = ' -n "/sol_ipcmk_${BASHPID}_default"' if kind.startswith('posix-') else ''
            script += f'ipcmk {options}{named} >{out} || exit 14\nipcmk_check {kind} {out} {amount} 644 || exit 15\n'
            # Permission filtering applies to named POSIX resources only.
            if kind.startswith('posix-'):
                options, amount = KINDS[kind]
                script += f'umask 077\nipcmk {options} -p 666 -n "/sol_ipcmk_${{BASHPID}}_umask" >{out} || exit 14\nipcmk_check {kind} {out} {amount} 600 || exit 15\n'
            else:
                script += f'umask 077\nipcmk {options} -p 666 >{out} || exit 14\nipcmk_check {kind} {out} {amount} 666 || exit 15\n'
            script += 'fds=(/proc/$$/fd/*); [[ ${#fds[@]} == "$before" ]] || exit 16\necho "owned resource properties, collisions, cleanup and fd stability passed"\n'
            run(a.binary, script, kind)
        invalid = [['--shmem='], ['--semaphore='], ['-Q', '--mode='], ['-s', '--name='], ['-s', '-n', '/' + 'x' * 300], [], ['-M'], ['-S'], ['-m'], ['-p'], ['-n'], ['--wat'], ['-Q', 'operand'], ['-Q', '--', 'x'], ['-Q', '-S', '2'], ['-Q', '-n', '/bad'], ['-s'], ['-q'], ['-m', '2'], ['-s', '-n', 'relative'], ['-s', '-n', '/'], ['-s', '-n', '/a/b']]
        for option in ('-M', '-m', '-S'):
            for value in ('', '-1', '+1', ' 1', '0', '1junk', '18446744073709551616', '18446744073709551615K'):
                invalid.append([option, value])
        for value in ('', '-0', '+1', ' 600', '888', '1000', '9999999999999999999999'):
            invalid.append(['-Q', '-p', value])
        invalid.extend([['-S', '2147483648'], ['-S', '2147483647'], ['-M', '18446744073709551615'], ['-m', '18446744073709551615', '-n', f'/sol_ipcmk_range_{os.getpid()}']])
        script = start
        for args in invalid:
            command = shlex.join(['ipcmk'] + args)
            script += f'if {command} >{out} 2>{out}.err; then echo {shlex.quote("unexpected success: " + command)}; exit 20; fi\n[[ ! -s {out} && -s {out}.err ]] || exit 21\n'
        # Repeated help/version, and recovery after stdout errors.
        script += f'for ((i=0;i<3;i++)); do ipcmk --help >{out} || exit 22; ipcmk --version >{out} || exit 23; done\n'
        script += 'if ipcmk --help >/dev/full 2>/dev/null; then exit 24; fi\n'
        script += cycle('shm', out)
        # Attached, long-equals and end-of-options forms preserve the old surface.
        for options, kind, amount, mode in [('-M1KiB -p0600', 'shm', 1024, '600'), ('--shmem=2K --mode=640 --', 'shm', 2048, '640'), ('--semaphore=7 --mode=660', 'sem', 7, '660'), ('--queue', 'msg', 0, '644'), ('--posix-shmem=4097 --name="/sol_ipcmk_${BASHPID}_long" --mode=600', 'posix-shm', 4097, '600'), ('-m4097 -n"/sol_ipcmk_${BASHPID}_short" -p600', 'posix-shm', 4097, '600'), ('--posix-semaphore --name="/sol_ipcmk_${BASHPID}_sem" -p600', 'posix-sem', 0, '600'), ('--posix-mqueue --name="/sol_ipcmk_${BASHPID}_mq" -p600', 'posix-msg', 0, '600')]:
            script += f'ipcmk {options} >{out} || exit 25\nipcmk_check {kind} {out} {amount} {mode} || exit 26\n'
        # Check the required native companion's explicit policy gate on an owned id.
        script += f'ipcmk -Q -p600 >{out} || exit 27\nread -r _ _ _ id <{out}\nif ipcctl --rm msg "$id" 2>/dev/null; then exit 28; fi\nif ! BASHOS_IPCRM_ALLOW_RMID=1 ipcctl --rm msg "$id"; then ipcmk_check msg {out} 0 600; exit 29; fi\n'
        script += 'echo "parser bounds, aliases, help/output recovery and companion cleanup passed"\n'
        run(a.binary, script, f'{len(invalid)} invalid cases and syntax/state')
    print('PASS: six real resource types, no skipped cases')


if __name__ == '__main__':
    main()
