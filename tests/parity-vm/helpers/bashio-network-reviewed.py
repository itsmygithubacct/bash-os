#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Guest-only, unprivileged negative controls for bashio network operations."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HOME = Path('/tmp/parity-home')
CASES = {
    'addr-missing': (2, 'set-addr needs IFACE IP MASK'),
    'addr-bad-ip': (2, 'bad IP:'),
    'addr-perm': (1, 'SIOCSIFADDR lo 192.0.2.20: Operation not permitted'),
    'route-missing': (2, 'set-route needs GATEWAY'),
    'route-missing-iface': (2, '-i needs IFACE'),
    'route-extra': (2, 'set-route: extra arg'),
    'route-bad-gateway': (2, 'bad GATEWAY:'),
    'route-long-iface': (2, 'interface name too long:'),
    'route-perm': (1, 'SIOCADDRT via 192.0.2.1: Operation not permitted'),
}
CONTROL = r'''#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0), rc, err;
  struct ifreq ifr;
  struct rtentry rt;
  struct sockaddr_in *addr;
  if (fd < 0 || if_nametoindex("lo") == 0) { perror("control setup"); return 90; }
  memset(&ifr, 0, sizeof ifr);
  strcpy(ifr.ifr_name, "lo");
  addr = (struct sockaddr_in *)&ifr.ifr_addr;
  addr->sin_family = AF_INET;
  if (inet_pton(AF_INET, "192.0.2.20", &addr->sin_addr) != 1) return 91;
  errno = 0; rc = ioctl(fd, SIOCSIFADDR, &ifr); err = errno;
  printf("SIOCSIFADDR rc=%d errno=%d\n", rc, err);
  if (rc != -1 || err != EPERM) return 92;
  memset(&rt, 0, sizeof rt);
  ((struct sockaddr_in *)&rt.rt_dst)->sin_family = AF_INET;
  ((struct sockaddr_in *)&rt.rt_genmask)->sin_family = AF_INET;
  addr = (struct sockaddr_in *)&rt.rt_gateway;
  addr->sin_family = AF_INET;
  if (inet_pton(AF_INET, "192.0.2.1", &addr->sin_addr) != 1) return 93;
  rt.rt_flags = RTF_UP | RTF_GATEWAY;
  errno = 0; rc = ioctl(fd, SIOCADDRT, &rt); err = errno;
  printf("SIOCADDRT rc=%d errno=%d\n", rc, err);
  close(fd);
  return rc == -1 && err == EPERM ? 0 : 94;
}
'''


def identity():
    marker = str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    product = str(uuid.UUID(Path('/sys/class/dmi/id/product_uuid').read_text().strip()))
    if (marker != product or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or os.getuid() != 2000 or os.geteuid() != 2000
            or Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME)):
        raise RuntimeError('not the designated uid-2000 parity guest')


def no_net_admin(pid):
    fields = {}
    for line in Path('/proc/%d/status' % pid).read_text().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            fields[key] = value.strip()
    uid = fields['Uid'].split()
    if len(uid) != 4 or uid[0:2] != ['2000', '2000']:
        raise RuntimeError('unexpected process UID')
    cap = int(fields['CapEff'], 16)
    if cap & (1 << 12):
        raise RuntimeError('CAP_NET_ADMIN present')
    return {'pid': pid, 'uid': uid, 'cap_eff': fields['CapEff'], 'net_admin': False}


def assess_values(case, status, out, err):
    expected, fragment = CASES[case]
    return (status == expected and out == b'' and 0 < len(err) <= 65536
            and fragment.encode() in err)


def setup():
    info = no_net_admin(os.getpid())
    for key, (status, fragment) in CASES.items():
        assert assess_values(key, status, b'', fragment.encode())
        assert not assess_values(key, status + 1, b'', fragment.encode())
        assert not assess_values(key, status, b'x', fragment.encode())
        assert not assess_values(key, status, b'', b'')
        assert not assess_values(key, status, b'', fragment.encode() + b'x' * 65536)
    (HOME / 'native-control.c').write_text(CONTROL)
    build = subprocess.run(['/usr/bin/gcc', '-Wall', '-Wextra', '-O2', '-o',
                            str(HOME / 'native-control'), str(HOME / 'native-control.c')],
                           capture_output=True, timeout=15)
    (HOME / 'compiler.stdout').write_bytes(build.stdout)
    (HOME / 'compiler.stderr').write_bytes(build.stderr)
    if build.returncode:
        raise RuntimeError('native control compilation failed: %s' % build.returncode)
    native = subprocess.run([str(HOME / 'native-control')], capture_output=True, timeout=5)
    (HOME / 'control.stdout').write_bytes(native.stdout)
    (HOME / 'control.stderr').write_bytes(native.stderr)
    (HOME / 'control.status').write_text(str(native.returncode) + '\n')
    if native.returncode != 0 or native.stderr or native.stdout != (
            b'SIOCSIFADDR rc=-1 errno=1\nSIOCADDRT rc=-1 errno=1\n'):
        raise RuntimeError('native EPERM control failed')
    (HOME / 'setup.json').write_text(json.dumps({'identity': info, 'parser_controls': len(CASES) * 5,
                                                  'native_control': 'EPERM for both ioctls'}) + '\n')


def guard():
    # The parent is the candidate shell that will issue the next operation.
    value = {'observer': no_net_admin(os.getpid()), 'candidate_shell': no_net_admin(os.getppid())}
    (HOME / 'candidate-precondition.json').write_text(json.dumps(value) + '\n')


def assess(case):
    if case not in CASES:
        raise ValueError('unknown case')
    raw = (HOME / 'candidate.status').read_text()
    if not re.fullmatch(r'[0-9]+\n', raw):
        raise ValueError('candidate status missing or malformed')
    status = int(raw)
    out = (HOME / 'candidate.stdout').read_bytes()
    err = (HOME / 'candidate.stderr').read_bytes()
    ok = assess_values(case, status, out, err)
    (HOME / 'assertion.json').write_text(json.dumps({'case': case, 'status': status,
                                                     'stdout_bytes': len(out), 'stderr_bytes': len(err),
                                                     'matched': ok}) + '\n')
    if not ok:
        print('candidate mismatch: ' + case, file=sys.stderr)
        return 1
    print('observed ' + case)
    return 0


def main():
    identity()
    if sys.argv[1:] == ['setup']:
        setup()
        return 0
    if sys.argv[1:] == ['guard']:
        guard()
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'assess':
        return assess(sys.argv[2])
    raise ValueError('expected setup, guard, or assess CASE')


if __name__ == '__main__':
    raise SystemExit(main())
