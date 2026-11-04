#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent, guest-only controls for firewall restore and backend errors.

Run only in a disposable VM inside the suite's fresh user/network namespace.
The kernel CLI is the oracle for set contents; a failing PATH shim is a
separate invocation control and must never stand in for kernel parity.
"""
import importlib.util
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('netlib', HERE/'mig-w1-netlib.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
IPSET = '/usr/sbin/ipset'


def call(argv):
    rc, out, err = L.run(argv)
    print('reference argv=%r rc=%r stdout=%r stderr=%r' % (argv, rc, out, err), file=sys.stderr, flush=True)
    return rc, out, err


def require(label, result):
    rc, out, err = result
    if not L.check(label, rc == 0, 'rc=%s stdout=%r stderr=%r' % (rc, out, err)):
        raise RuntimeError(label + ' setup/control failed')
    return out


def fw(*args, env=None):
    result = L.cand('fw "$@"', '-B', 'iptables', *args, env=env)
    print('candidate argv=%r rc=%r stdout=%r stderr=%r' % (args, *result), file=sys.stderr, flush=True)
    return result


def members(name):
    text = require('reference save ' + name, call([IPSET, 'save', name]))
    return sorted(line for line in text.splitlines() if line.startswith('add ' + name + ' '))


def real_restore():
    saved = '/tmp/parity-case/takeover-fw-independent.rules'
    # Direct reference setup and positive/negative controls must succeed before
    # candidate observations can be interpreted.
    require('reference create target', call([IPSET, 'create', 'r11_target', 'hash:ip']))
    require('reference add saved member', call([IPSET, 'add', 'r11_target', '192.0.2.10']))
    require('candidate reset', fw('reset'))
    require('candidate save', fw('save', saved))
    require('reference add drift', call([IPSET, 'add', 'r11_target', '192.0.2.11']))
    require('reference create unrelated', call([IPSET, 'create', 'r11_unrelated', 'hash:ip']))
    require('reference add unrelated member', call([IPSET, 'add', 'r11_unrelated', '198.51.100.44']))
    before_unrelated = members('r11_unrelated')
    L.check('positive drift control', len(members('r11_target')) == 2)
    rc, out, err = fw('restore', saved)
    L.check('restore succeeds', rc == 0, 'rc=%r stdout=%r stderr=%r' % (rc, out, err))
    L.check('saved target restored exactly', members('r11_target') == ['add r11_target 192.0.2.10'])
    L.check('unrelated post-save set survives', members('r11_unrelated') == before_unrelated)
    rc, out, err = call([IPSET, 'test', 'r11_target', '192.0.2.11'])
    L.check('independent negative membership control', rc == 1, 'rc=%r stdout=%r stderr=%r' % (rc, out, err))


def failing_backend():
    base = pathlib.Path('/tmp/parity-case/takeover-fw-failbin')
    base.mkdir(parents=True, exist_ok=True)
    log = base/'calls'
    for name in ('iptables', 'ip6tables'):
        p = base/name
        p.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$TAKEOVER_FW_CALLS"\nprintf "%s\\n" "injected backend denial" >&2\nexit 79\n')
        p.chmod(0o755)
    env = {'PATH': str(base) + ':/usr/sbin:/usr/bin:/sbin:/bin', 'TAKEOVER_FW_CALLS': str(log)}
    rc, out, err = fw('reset', env=env)
    calls = log.read_text() if log.exists() else ''
    L.check('failing backend was actually invoked', bool(calls), 'calls=%r' % calls)
    L.check('reset reports backend failure', rc != 0, 'rc=%r stdout=%r stderr=%r calls=%r' % (rc, out, err, calls))
    L.check('backend denial is observable', 'injected backend denial' in err, 'stderr=%r' % err)


if __name__ == '__main__':
    scenario = sys.argv[1]
    try:
        {'real-restore': real_restore, 'failing-backend': failing_backend}[scenario]()
    except Exception as exc:
        L.check('fixture completed', False, repr(exc))
    sys.exit(L.finish(scenario))
