#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run only in the disposable parity VM; block every swapon syscall."""
import ctypes
import os
import platform
import re
import subprocess
import sys

class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]

class Program(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]


def inject(code):
    # x86-64 __NR_swapon=167. The filter is installed before exec and never
    # forwards swapon; independent controls verify each injected result.
    instructions = (Filter * 4)(Filter(0x20, 0, 0, 0),
                                 Filter(0x15, 0, 1, 167),
                                 Filter(0x06, 0, 0, 0x00050000 | code),
                                 Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program)):
        os._exit(125)


def setup_error(message):
    print('SETUP ERROR: ' + message, file=sys.stderr)
    raise SystemExit(125)


def main():
    if platform.machine() != 'x86_64' or os.geteuid() != 2000:
        setup_error('requires x86_64 VM and uid 2000')
    if open('/sys/class/dmi/id/sys_vendor').read().strip() != 'QEMU':
        setup_error('requires QEMU guest')
    if not re.fullmatch(r'[0-9a-fA-F-]{36}', open('/etc/bashos-parity-vm').read().strip()):
        setup_error('missing VM marker')
    bash = sys.argv[1]
    env = dict(os.environ, LC_ALL='C')
    control = ('import ctypes,sys; l=ctypes.CDLL(None,use_errno=True); '
               'r=l.swapon(b"/fixture-control",0); '
               'sys.exit(0 if r == -1 and ctypes.get_errno() == int(sys.argv[1]) else 98)')
    for code, message in [(1, 'Operation not permitted'),
                          (2, 'No such file or directory'),
                          (22, 'Invalid argument'),
                          (16, 'Device or resource busy')]:
        run = lambda args: subprocess.run(args, env=env, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, timeout=10,
                                          preexec_fn=lambda: inject(code))
        probe = run([sys.executable, '-c', control, str(code)])
        if probe.returncode != 0:
            setup_error('injection control failed for %d: %r' % (code, probe.stderr))
        path = '/fixture path/error-%d' % code
        result = run([bash, '--noprofile', '--norc', '-c',
                      '[[ $(type -t swapon) == builtin ]] || exit 99; swapon -- "$1"',
                      'swapon-test', path])
        suffix = ('swapon: %s: %s\n' % (path, message)).encode()
        if result.returncode != 1 or result.stdout or not result.stderr.endswith(suffix) or result.stderr.count(b'\n') != 1:
            raise SystemExit('FAIL errno=%d status=%d stdout=%r stderr=%r' %
                             (code, result.returncode, result.stdout, result.stderr))
    print('swapon errno contract: ok')

if __name__ == '__main__':
    main()
