#!/usr/bin/env python3
"""Check production keyctl code with closed fixtures and owned kernel children.

No compilation or timing occurs here. A blocked kernel probe is reported as
blocked, separately from fixture passes, and never falls through to inherited
session mutations.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def environment(preload=None):
    env = dict(os.environ, LC_ALL='C')
    env.pop('BASH_ENV', None)
    env.pop('ENV', None)
    if preload:
        env.update(LD_PRELOAD=str(preload),
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def invoke(binary, script, preload=None, data=None):
    return subprocess.run([str(binary), '--noprofile', '--norc', '-c', script],
                          env=environment(preload), input=b'' if data is None else data, capture_output=True,
                          timeout=30)


def setup(module):
    return (f'enable -f {shlex.quote(str(module))} keyctl keyctl_fixture || exit 90\n'
            'PATH=\nkeyctl_fixture reset || exit 91\n')


def real_check(binary, directory, preload=None, module=None):
    """All mutations execute after a successful anonymous join in this child."""
    d = shlex.quote(str(directory))
    load = f'enable -f {shlex.quote(str(module))} keyctl || exit 90\n' if module else ''
    script = load + f'''
PATH=
[[ $(type -t keyctl) == builtin ]] || exit 91
keyctl session >{d}/ring 2>{d}/session-error
s=$?
if ((s)); then
    printf 'KERNEL_BLOCKED session status=%s\n' "$s"
    exit 77
fi
read -r ring <{d}/ring
[[ $ring =~ ^[1-9][0-9]*$ ]] || exit 92
# Only this newly created anonymous ring is ever cleaned up. No @s cleanup
# runs on a failed join, and no parent shell runs a mutating command.
trap 'keyctl clear "$ring" >/dev/null; keyctl revoke "$ring" >/dev/null' EXIT
for ((i=0;i<20;i++)); do
    keyctl add user binary "$ring" <{d}/payload >{d}/id || exit 93
    read -r id <{d}/id
    [[ $id =~ ^[1-9][0-9]*$ ]] || exit 94
    keyctl search "$ring" user binary >{d}/found || exit 95
    read -r found <{d}/found
    [[ $found == "$id" ]] || exit 96
    keyctl print "$id" >{d}/kernel-output-$i || exit 97
    # A second add updates the existing key; check its identity and bytes.
    keyctl add user binary <{d}/payload >{d}/updated || exit 98
    read -r updated <{d}/updated
    [[ $updated == "$id" ]] || exit 99
    keyctl revoke "$id" || exit 100
    keyctl print "$id" >{d}/revoked-output 2>{d}/revoked-error && exit 101
    keyctl search "$ring" user missing >{d}/missing-output 2>{d}/missing-error && exit 102
    keyctl clear "$ring" && keyctl clear "$ring" || exit 103
done
keyctl search "$ring" user binary >{d}/cleared-output 2>{d}/cleared-error && exit 104
printf 'KERNEL_PASS cycles=20\n'
'''
    r = invoke(binary, script, preload)
    diagnostic = (directory / 'session-error').read_text()
    if r.returncode == 77:
        if not any(os.strerror(e) in diagnostic for e in
                   (errno.EPERM, errno.EACCES, errno.ENOSYS)):
            raise AssertionError(('unexpected kernel block', diagnostic, r))
        return dict(status='blocked', exit_code=77, stdout=r.stdout.decode(),
                    diagnostic=diagnostic, scope='anonymous join denied; no later kernel operations attempted')
    assert r.returncode == 0 and r.stdout == b'KERNEL_PASS cycles=20\n' and not r.stderr, r
    for i in range(20):
        assert (directory / f'kernel-output-{i}').read_bytes() == (directory / 'payload').read_bytes()
    for name in ('revoked-output', 'missing-output', 'cleared-output'):
        assert not (directory / name).read_bytes(), name
    return dict(status='passed', cycles=20, scope='owned anonymous child session only',
                payload_bytes=(directory / 'payload').stat().st_size,
                payload_sha256=hashlib.sha256((directory / 'payload').read_bytes()).hexdigest(),
                diagnostics={name: (directory / name).read_text() for name in
                             ('revoked-error', 'missing-error', 'cleared-error')})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--module', type=Path, required=True)
    p.add_argument('--preload', type=Path)
    p.add_argument('--real-module', type=Path)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--regressions-only', action='store_true')
    args = p.parse_args()
    binary, module = args.binary.resolve(), args.module.resolve()
    prefix = setup(module)
    cases = []
    with tempfile.TemporaryDirectory(prefix='sol-keyctl-') as temp:
        d = Path(temp)
        payload = bytes(range(256)) * 16 + b'\0tail\xff\n'
        (d / 'payload').write_bytes(payload)
        (d / 'small').write_bytes(b'tiny\0binary')
        (d / 'empty').write_bytes(b'')
        (d / 'max').write_bytes(b'x' * 1048575)
        (d / 'oversize').write_bytes(b'x' * 1048576)
        (d / 'user-max').write_bytes(b'u' * 32767)
        (d / 'user-oversize').write_bytes(b'u' * 32768)
        q = shlex.quote(str(d))
        add = f'keyctl add user binary <{q}/payload'
        joined = 'keyctl session >/dev/null || exit 92\n'

        def check(name, body, expected=b'', status=0, diagnostic=None, join=True):
            # Preserve the command's status while checking every path for leaked
            # production buffers and malformed boundary requests.
            footer = '\nsaved=$?\nkeyctl_fixture check || exit 125\nexit "$saved"\n'
            r = invoke(binary, prefix + (joined if join else '') + body + footer, args.preload)
            good = (r.returncode == status and r.stdout == expected and
                    (diagnostic.encode() in r.stderr if diagnostic else not r.stderr))
            cases.append(dict(name=name, status='passed' if good else 'failed',
                              exit_code=r.returncode, expected_status=status,
                              stdout_hex=r.stdout.hex(), stderr=r.stderr.decode(errors='replace')))
            print('PASS' if good else 'FAIL', name, flush=True)
            if not good:
                print('  actual:', r.returncode, repr(r.stdout), repr(r.stderr),
                      'expected:', status, repr(expected), flush=True)

        # Regression oracles fail on the historical wrapper, before timing.
        for words in [('session', 'name', 'extra'), ('add', 'user', 'name', '@s', 'extra'),
                      ('search', '@s', 'user', 'name', 'extra')]:
            check('extra operands ' + words[0], shlex.join(['keyctl', *words]),
                  status=2, diagnostic=words[0])
        check('serial ABI overflow', 'keyctl print 4294977297', status=2,
              diagnostic='invalid serial')
        check('empty ring is invalid', 'keyctl clear ""', status=2, diagnostic='invalid keyring')
        check('buffered payload output failure', f'keyctl add user small <{q}/small >/dev/null\n'
              'keyctl print 10001 >/dev/full', status=1, diagnostic='write stdout')
        check('buffered serial output failure', 'keyctl session >/dev/full',
              status=1, diagnostic='write stdout')
        if not args.regressions_only:
            check('native help and empty PATH', '[[ $(type -t keyctl) == builtin ]] && help keyctl >/dev/null')
            check('anonymous private session', 'keyctl session\nkeyctl_fixture stats',
                  b'9001\ncalls=1 bad=0 joined=1 linked=0 revoked=0 ring=0\n', join=False)
            check('named session', 'keyctl session fixture-owned\nkeyctl_fixture session-name',
                  b'9001\nfixture-owned\n', join=False)
            check('anonymous session passes NULL', 'keyctl session\nkeyctl_fixture session-name',
                  b'9001\n<anonymous>\n', join=False)
            check('empty session name remains named', 'keyctl session ""\nkeyctl_fixture session-name',
                  b'9001\n\n', join=False)
            check('binary add search print', add + '\nkeyctl search user binary\nkeyctl print 10001',
                  b'10001\n10001\n' + payload)
            check('explicit ring and update', add + '\n' + add + ' 9001\n'
                  'keyctl search 9001 user binary\nkeyctl_fixture stats',
                  b'10001\n10001\n10001\ncalls=4 bad=0 joined=1 linked=1 revoked=0 ring=9001\n')
            check('empty generic payload', f'keyctl add fixture empty <{q}/empty\nkeyctl print 10001', b'10001\n')
            check('maximum generic payload', f'keyctl add fixture max <{q}/max >/dev/null\n'
                  'keyctl print 10001', b'x' * 1048575)
            check('oversized payload bounded without syscall',
                  f'keyctl add fixture huge <{q}/oversize\nprintf "status=%s\\n" "$?"\nkeyctl_fixture stats',
                  b'status=1\ncalls=1 bad=0 joined=1 linked=0 revoked=0 ring=0\n', diagnostic='Argument list too long')
            check('empty user payload rejected by type', f'keyctl add user empty <{q}/empty',
                  status=1, diagnostic='Invalid argument')
            check('user type maximum payload', f'keyctl add user max <{q}/user-max >/dev/null\n'
                  'keyctl print 10001', b'u' * 32767)
            check('user type oversized payload rejected', f'keyctl add user huge <{q}/user-oversize',
                  status=1, diagnostic='Invalid argument')
            check('user type empty name rejected', f'keyctl add user "" <{q}/payload',
                  status=1, diagnostic='Invalid argument')
            check('missing key', 'keyctl print 12345', status=1, diagnostic='Required key not available')
            check('missing search', 'keyctl search user missing', status=1, diagnostic='Required key not available')
            check('revoked key', add + ' >/dev/null\nkeyctl revoke 10001\nkeyctl print 10001',
                  status=1, diagnostic='Key has been revoked')
            check('revoked key not searchable', add + ' >/dev/null\nkeyctl revoke 10001\nkeyctl search user binary',
                  status=1, diagnostic='Required key not available')
            check('repeated revoke and clear', add + ' >/dev/null\nkeyctl revoke 10001\n'
                  'keyctl revoke 10001\nkeyctl clear\nkeyctl clear\nkeyctl_fixture stats',
                  b'calls=6 bad=0 joined=1 linked=0 revoked=1 ring=-3\n')
            check('clear removes search link', add + ' >/dev/null\nkeyctl clear\nkeyctl search user binary',
                  status=1, diagnostic='Required key not available')
            # Exact argument values arriving at the real invocation boundary.
            for alias, value in [('@s', -3), ('@t', -1), ('@p', -2), ('@u', -4),
                                 ('@us', -5), ('@g', -6), ('9001', 9001),
                                 ('2147483647', 2147483647), ('-2147483648', -2147483648)]:
                check('ring ABI ' + alias,
                      f'keyctl_fixture ring {value}\n{add} {alias}\n'
                      f'keyctl search {alias} user binary\nkeyctl clear {alias}\nkeyctl_fixture stats',
                      f'10001\n10001\ncalls=4 bad=0 joined=1 linked=0 revoked=0 ring={value}\n'.encode())
            for verb in ('print', 'revoke', 'clear'):
                for value in ('', '+1', ' 1', '1 ', '-', '1x', '2147483648', '-2147483649', '9' * 80):
                    check(verb + ' invalid serial ' + repr(value), shlex.join(['keyctl', verb, value]),
                          status=2, diagnostic='invalid')
            for words in [[], ['bogus'], ['add'], ['add', 'user'], ['search'], ['search', 'user'],
                          ['print'], ['print', '1', '2'], ['revoke'], ['revoke', '1', '2'],
                          ['clear', '@s', 'extra']]:
                check('usage ' + repr(words), shlex.join(['keyctl', *words]), status=2,
                      diagnostic='keyctl')
            for words in [['add', '', 'name'], ['add', 'a' * 32, 'name'],
                          ['search', '.reserved', 'name'], ['search', 'a' * 32, 'name'],
                          ['add', 'user', 'n' * 4096], ['search', 'user', 'n' * 4096],
                          ['session', 'n' * 4096], ['session', '.reserved'],
                          ['add', 'keyring', '.reserved']]:
                check('type/name validation ' + repr([w[:45] for w in words]),
                      shlex.join(['keyctl', *words]), status=2, diagnostic='keyctl')
            check('maximum type and description lengths',
                  shlex.join(['keyctl', 'add', 't' * 31, 'n' * 4095]) + f' <{q}/payload\n'
                  + shlex.join(['keyctl', 'search', 't' * 31, 'n' * 4095]), b'10001\n10001\n')
            check('maximum session name', shlex.join(['keyctl', 'session', 's' * 4095]), b'9001\n')
            check('closed stdin', 'keyctl add user name <&-', status=1, diagnostic='Bad file descriptor')
            check('directory stdin', f'keyctl add user name <{q}', status=1, diagnostic='Is a directory')
            check('interrupted stdin resumes', f'keyctl_fixture input-error {errno.EINTR}\n'
                  + add + '\nkeyctl print 10001\nkeyctl_fixture memory',
                  b'10001\n' + payload + b'live=0\n')
            check('failed stdin does not add or leak', f'keyctl_fixture input-error {errno.EIO}\n'
                  + add + '\nprintf "status=%s\\n" "$?"\nkeyctl_fixture memory\nkeyctl_fixture stats',
                  b'status=1\nlive=0\ncalls=1 bad=0 joined=1 linked=0 revoked=0 ring=0\n',
                  diagnostic='Input/output error')
            for attempt in (1, 2):
                check(f'add allocation failure {attempt}', f'keyctl_fixture alloc-fail {attempt}\n'
                      + add + '\nprintf "status=%s\\n" "$?"\nkeyctl_fixture memory\nkeyctl_fixture stats',
                      b'status=1\nlive=0\ncalls=1 bad=0 joined=1 linked=0 revoked=0 ring=0\n',
                      diagnostic='Cannot allocate memory')
            for attempt in (1, 2):
                check(f'print allocation failure {attempt}', add + ' >/dev/null\n'
                      f'keyctl_fixture mode 1\nkeyctl_fixture alloc-fail {attempt}\n'
                      'keyctl print 10001\nprintf "status=%s\\n" "$?"\nkeyctl_fixture memory',
                      b'status=1\nlive=0\n')
            for mode in (1, 2, 4):
                check('read size race ' + str(mode), add + ' >/dev/null\n'
                      f'keyctl_fixture mode {mode}\nkeyctl print 10001', payload)
            check('bounded growth retries', add + ' >/dev/null\nkeyctl_fixture mode 3\nkeyctl print 10001',
                  status=1, diagnostic='payload keeps growing')
            check('revoked between reads', add + ' >/dev/null\nkeyctl_fixture mode 5\nkeyctl print 10001',
                  status=1, diagnostic='Key has been revoked')
            for op, command in [('session', 'keyctl session'), ('add', add),
                                ('search', 'keyctl search user binary'), ('probe', 'keyctl print 10001'),
                                ('read', 'keyctl print 10001'), ('revoke', 'keyctl revoke 10001'),
                                ('clear', 'keyctl clear')]:
                for error in (errno.EACCES, errno.EPERM, errno.ENOSYS):
                    check(f'denied {op} errno={error}', add + ' >/dev/null\n'
                          f'keyctl_fixture fail {op} {error}\n{command}',
                          status=1, diagnostic=os.strerror(error))
            check('output error recovery', add + ' >/dev/null\nkeyctl print 10001 >/dev/full\n'
                  '[[ $? == 1 ]] || exit 93\nkeyctl print 10001', payload, diagnostic='write stdout')
            check('serial output error recovery', 'keyctl session >/dev/full\n'
                  '[[ $? == 1 ]] || exit 93\nkeyctl session', b'9001\n', diagnostic='write stdout')
            # Redirections are all owned by Bash; the loadable must not close or leak them.
            check('500 repeated add/search/print/clear cycles and FD ownership', f'''
exec 8<{q}/payload
before=(/proc/$$/fd/*)
for ((i=0;i<500;i++)); do
    keyctl_fixture reset
    keyctl session >/dev/null || exit 94
    {add} >/dev/null || exit 95
    keyctl search user binary >/dev/null || exit 96
    keyctl print 10001 >/dev/null || exit 97
    keyctl clear && keyctl clear || exit 98
    keyctl_fixture check || exit 99
done
after=(/proc/$$/fd/*)
[[ ${{#before[@]}} == ${{#after[@]}} ]] || exit 100
read -r -N 1 -u 8 first || exit 101
exec 8<&-
keyctl_fixture reset
keyctl_fixture stats
''', b'calls=0 bad=0 joined=0 linked=0 revoked=0 ring=0\n')
        kernel = (dict(status='not-run', reason='regression-only baseline') if args.regressions_only
                  else real_check(binary, d, args.preload, args.real_module))
    report = dict(cases=cases, kernel=kernel,
                  passed=sum(c['status'] == 'passed' for c in cases),
                  failed=sum(c['status'] == 'failed' for c in cases))
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'failed', 'kernel')}, indent=2))
    return bool(report['failed'])


if __name__ == '__main__':
    raise SystemExit(main())
