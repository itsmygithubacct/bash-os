#!/usr/bin/env python3
"""Focused ipcctl tests. No compilation; all real IPC objects are IPC_PRIVATE.

The closed shim includes production ipcctl.c and records exact requests. Native
allocation failures are disclosed in the JSON report, never counted as passes.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KINDS = ('shm', 'msg', 'sem')
IDS = (17, 231, 4096)
USAGE = 'Usage: ipcctl --rm shm|msg|sem <id>\n'
DENIED = 'ipcctl: removal not permitted by policy (read-only mode)\n'


def environment(preload=None):
    env = dict(os.environ, LC_ALL='C')
    for key in ('BASH_ENV', 'ENV', 'BASHOS_IPCRM_ALLOW_RMID', 'LD_PRELOAD'):
        env.pop(key, None)
    if preload:
        env.update(LD_PRELOAD=str(preload), ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def invoke(binary, body, module=None, preload=None):
    prefix = 'PATH=\n'
    if module:
        prefix += f'enable -f {shlex.quote(str(module))} ipcctl ipcctl_fixture || exit 90\n'
        prefix += 'ipcctl_fixture reset || exit 91\n'
    return subprocess.run([str(binary), '--noprofile', '--norc', '-c', prefix + body],
                          env=environment(preload), capture_output=True, text=True, timeout=30)


def trace(calls=0, active='111', records=''):
    return records + f'calls {calls} bad 0 active {active}\n'


class PrivateIPC:
    """Linux SysV IPC ABI, with cleanup restricted to this instance's IDs."""
    def __init__(self):
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.lib.shmget.argtypes = (ctypes.c_int, ctypes.c_size_t, ctypes.c_int)
        self.lib.msgget.argtypes = (ctypes.c_int, ctypes.c_int)
        self.lib.semget.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
        self.lib.shmctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        self.lib.msgctl.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        self.owned = set()

    def create(self, kind):
        if kind == 'shm':
            ident = self.lib.shmget(0, 4096, 0o600)
        elif kind == 'msg':
            ident = self.lib.msgget(0, 0o600)
        else:
            ident = self.lib.semget(0, 1, 0o600)
        if ident < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), kind)
        self.owned.add((kind, ident))
        return ident

    def ctl(self, kind, ident, command):
        buf = ctypes.create_string_buffer(4096)
        ctypes.set_errno(0)
        if kind == 'sem':
            rc = self.lib.semctl(ident, 0, command, ctypes.byref(buf))
        else:
            rc = getattr(self.lib, kind + 'ctl')(ident, command, ctypes.byref(buf))
        return rc, ctypes.get_errno()

    def alive(self, resource):
        rc, code = self.ctl(*resource, 2)  # IPC_STAT
        if rc < 0 and code not in (errno.EINVAL, errno.EIDRM):
            raise OSError(code, os.strerror(code))
        return rc >= 0

    def cleanup(self):
        for resource in self.owned:
            rc, code = self.ctl(*resource, 0)  # IPC_RMID
            if rc < 0 and code not in (errno.EINVAL, errno.EIDRM):
                raise OSError(code, os.strerror(code))
        self.owned.clear()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--preload', type=Path)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--shim-only', action='store_true')
    args = p.parse_args()
    binary, module = args.binary.resolve(), args.module.resolve()
    cases = []

    def record(name, good, detail=None):
        cases.append(dict(name=name, status='pass' if good else 'fail', detail=detail))
        print('PASS' if good else 'FAIL', name, '' if good else repr(detail), flush=True)

    def check(name, body, expected='', status=0, diagnostic='', native=False):
        r = invoke(binary, body, None if native else module, args.preload)
        good = (r.returncode == status and r.stdout == expected and r.stderr == diagnostic)
        record(name, good, dict(exit=r.returncode, stdout=r.stdout, stderr=r.stderr,
                               expected=dict(exit=status, stdout=expected, stderr=diagnostic)))
        return good

    def checked_call(command, policy='export BASHOS_IPCRM_ALLOW_RMID=1'):
        return policy + '\n' + command + '\nrc=$?\nipcctl_fixture trace\nexit "$rc"'

    # All malformed inputs are confined to the closed fixture, even on failure.
    for argv in ([], ['--rm'], ['--rm', 'shm'], ['--rm', 'msg'], ['--rm', 'sem'],
                 ['--rm', 'shm', '17', 'extra'], ['--bad'], ['--rm', 'SHM', '17'],
                 ['--rm', '', '17'], ['--rm', 'other', '17']):
        for allow in (False, True):
            check(f'syntax {argv!r} allow={allow}',
                  checked_call(shlex.join(['ipcctl'] + argv),
                               'export BASHOS_IPCRM_ALLOW_RMID=1' if allow else
                               'unset BASHOS_IPCRM_ALLOW_RMID'), trace(), 1, USAGE)
    for token in ('', '-1', '-0', '+17', ' 17', '\t17', '17 ', '17\n', '17x',
                  '0x11', '1e1', '1.0', '2147483648', '4294967296',
                  '9223372036854775808', '9' * 200, '١٧'):
        check('invalid ID ' + repr(token),
              checked_call(shlex.join(['ipcctl', '--rm', 'shm', token])),
              trace(), 1, f"ipcctl: invalid id '{token}'\n")
    for token in ('0', '000', '17', '00017', '2147483647'):
        ident = int(token)
        body = f'ipcctl_fixture reset {ident} 231 4096 0 0\n'
        body += checked_call(shlex.join(['ipcctl', '--rm', 'shm', token]))
        check('valid decimal boundary ' + token, body,
              trace(1, '011', f'shm {ident} 0 1\n'))
    for value in (None, '', '0', 'true', 'yes', '01', '1 ', ' 1', '1\n', '2'):
        policy = ('unset BASHOS_IPCRM_ALLOW_RMID' if value is None else
                  'export BASHOS_IPCRM_ALLOW_RMID=' + shlex.quote(value))
        for kind, ident in zip(KINDS, IDS):
            check(f'policy {value!r} {kind}',
                  checked_call(f'ipcctl --rm {kind} {ident}', policy), trace(), 1, DENIED)
    for index, (kind, ident) in enumerate(zip(KINDS, IDS)):
        active = ''.join('0' if n == index else '1' for n in range(3))
        check('exact request ' + kind, checked_call(f'ipcctl --rm {kind} {ident}'),
              trace(1, active, f'{kind} {ident} 0 1\n'))
        for code in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EIDRM, errno.ENOSYS, errno.EIO):
            check(f'errno {code} {kind}', f'ipcctl_fixture reset 17 231 4096 {code} 0\n' +
                  checked_call(f'ipcctl --rm {kind} {ident}'),
                  trace(1, '111', f'{kind} {ident} 0 1\n'), 1,
                  f'ipcctl: {kind} IPC_RMID failed for id {ident}: {os.strerror(code)}\n')
        check('removed ID ' + kind, 'export BASHOS_IPCRM_ALLOW_RMID=1\n' +
              f'ipcctl --rm {kind} {ident} || exit 92\n' +
              f'ipcctl --rm {kind} {ident}\nrc=$?\nipcctl_fixture trace\nexit "$rc"',
              trace(2, active, f'{kind} {ident} 0 1\n' * 2), 1,
              f'ipcctl: {kind} IPC_RMID failed for id {ident}: {os.strerror(errno.EINVAL)}\n')
    check('policy reread in one shell',
          'export BASHOS_IPCRM_ALLOW_RMID=1\nipcctl --rm shm 17 || exit 92\n'
          'export BASHOS_IPCRM_ALLOW_RMID=0\nipcctl --rm msg 231\n'
          '[[ $? == 1 ]] || exit 93\nexport BASHOS_IPCRM_ALLOW_RMID=1\n'
          'ipcctl --rm msg 231 || exit 94\nipcctl --rm sem 4096 || exit 95\n'
          'ipcctl_fixture verify', diagnostic=DENIED)
    check('temporary policy assignment does not persist',
          'unset BASHOS_IPCRM_ALLOW_RMID\n'
          'BASHOS_IPCRM_ALLOW_RMID=1 ipcctl --rm shm 17 || exit 92\n'
          'ipcctl --rm msg 231\nrc=$?\nipcctl_fixture trace\nexit "$rc"',
          trace(1, '011', 'shm 17 0 1\n'), 1, DENIED)
    check('100 reset/remove cycles and FD stability in one shell',
          'export BASHOS_IPCRM_ALLOW_RMID=1\nbefore=(/proc/$$/fd/*)\n'
          'for ((i=0;i<100;i++)); do\n'
          'ipcctl_fixture reset 17 231 4096 0 1 || exit 92\n'
          'ipcctl --rm shm 17 || exit 93\nipcctl --rm msg 231 || exit 94\n'
          'ipcctl --rm sem 4096 || exit 95\nipcctl_fixture verify || exit 96\ndone\n'
          'after=(/proc/$$/fd/*)\n[[ ${#before[@]} == ${#after[@]} ]] || exit 97\n'
          'printf "100 cycles, 300 validated removals, stable FDs\\n"',
          '100 cycles, 300 validated removals, stable FDs\n')
    check('100 syscall failures then successful reset in one shell',
          'export BASHOS_IPCRM_ALLOW_RMID=1\nipcctl_fixture reset 17 231 4096 5 1\n'
          'before=(/proc/$$/fd/*)\nfor ((i=0;i<100;i++)); do\n'
          'ipcctl --rm shm 17 2>/dev/null\n[[ $? == 1 ]] || exit 92\ndone\n'
          'ipcctl_fixture trace\nipcctl_fixture reset 17 231 4096 0 1\n'
          'ipcctl --rm shm 17 || exit 93\nipcctl --rm msg 231 || exit 94\n'
          'ipcctl --rm sem 4096 || exit 95\nipcctl_fixture verify || exit 96\n'
          'after=(/proc/$$/fd/*)\n[[ ${#before[@]} == ${#after[@]} ]]',
          trace(100))
    help_text = USAGE + 'Remove one System V IPC object when BASHOS_IPCRM_ALLOW_RMID=1.\n'
    for native in (False, True):
        for option, expected in (('--help', help_text), ('-h', help_text),
                                 ('--version', 'ipcctl 1.0 (bash-os)\n'),
                                 ('-V', 'ipcctl 1.0 (bash-os)\n')):
            check(f'help/version {option} native={native}', f'ipcctl {option}',
                  expected, native=native)
        for option in ('--help', '--version'):
            # A later successful call proves stdio state recovers in this shell.
            check(f'output failure/recovery {option} native={native}',
                  f'ipcctl {option} >/dev/full\nrc=$?\nipcctl --version || exit 98\nexit "$rc"',
                  'ipcctl 1.0 (bash-os)\n', 1, 'ipcctl: write error: No space left on device\n',
                  native=native)

    native_result = dict(status='not_requested' if args.shim_only else 'pending')
    if not args.shim_only:
        owned = PrivateIPC()
        try:
            resources = [(kind, owned.create(kind)) for _ in range(2) for kind in KINDS]
            native_result = dict(status='pass', resources=resources, allocation='IPC_PRIVATE 0600')
            for kind, ident in resources[:3]:
                for policy in ('unset BASHOS_IPCRM_ALLOW_RMID',
                               'export BASHOS_IPCRM_ALLOW_RMID=0',
                               'export BASHOS_IPCRM_ALLOW_RMID=true'):
                    check(f'native policy {kind} {policy}', policy +
                          f'\nipcctl --rm {kind} {ident}', status=1, diagnostic=DENIED, native=True)
                    record('native denial preserves all owned resources ' + kind,
                           all(owned.alive(r) for r in resources))
            removed = set()
            # First resource of each kind is removed; companions remain intact.
            for resource in resources:
                kind, ident = resource
                check(f'native allow {kind} {ident}', 'export BASHOS_IPCRM_ALLOW_RMID=1\n'
                      f'ipcctl --rm {kind} {ident} >/dev/full', native=True)
                removed.add(resource)
                if not owned.alive(resource):
                    owned.owned.discard(resource)
                record(f'native exact selection {kind} {ident}',
                       all(owned.alive(r) == (r not in removed) for r in resources))
                # This missing ID was created and removed by this harness.
                rc, code = owned.ctl(kind, ident, 0)
                record('native independent missing-ID oracle ' + kind,
                       rc == -1 and code in (errno.EINVAL, errno.EIDRM))
                check(f'native missing ID {kind} {ident}',
                      'export BASHOS_IPCRM_ALLOW_RMID=1\n' + f'ipcctl --rm {kind} {ident}',
                      status=1, native=True,
                      diagnostic=f'ipcctl: {kind} IPC_RMID failed for id {ident}: {os.strerror(code)}\n')
        except OSError as exc:
            native_result = dict(status='unavailable', errno=exc.errno, reason=str(exc),
                                 fallback='closed production-source syscall fixture')
            print('NATIVE UNAVAILABLE:', exc, '; using disclosed syscall fixture', flush=True)
            if exc.errno not in (errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOSPC, errno.ENOMEM):
                record('native unexpected allocation/control failure', False, str(exc))
        finally:
            owned.cleanup()
            native_result['cleanup'] = 'only IDs allocated by this harness; no global enumeration/removal'
    failed = sum(c['status'] == 'fail' for c in cases)
    if failed and native_result['status'] == 'pass':
        native_result['status'] = 'see_failed_cases'
    report = dict(status='fail' if failed else 'pass', passed=len(cases)-failed,
                  failed=failed, native=native_result, cases=cases)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'ipcctl: {report["passed"]} passed, {failed} failed; native={native_result["status"]}')
    return bool(failed)


if __name__ == '__main__':
    sys.exit(main())
