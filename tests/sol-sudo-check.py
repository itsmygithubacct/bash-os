#!/usr/bin/env python3
"""Noncompiling sudo checks: fixture groups, an independent request-digest
oracle, and optional native shell entry-point checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import struct
import subprocess
import tempfile

GROUPS = ['options', 'lookup', 'authority', 'translation', 'root', 'edit', 'helper',
          'command']

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--fixture', type=Path)
p.add_argument('--shell', type=Path)
p.add_argument('--report', type=Path, help='write per-case JSON statuses here')
a = p.parse_args()
assert a.fixture or a.shell, 'select --fixture and/or --shell'
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
cases = []


def case(name, ok, detail=''):
    cases.append(dict(case=name, status='pass' if ok else 'fail', detail=detail))
    print(('PASS ' if ok else 'FAIL ') + name + (': ' + detail if detail and not ok else ''), flush=True)
    return ok


if a.fixture:
    fixture = a.fixture.resolve()
    for group in GROUPS:
        with tempfile.TemporaryDirectory(prefix='sol-sudo-check-') as scratch:
            scratch = os.path.realpath(scratch)
            proc = subprocess.run([str(fixture), group], cwd=scratch, capture_output=True, timeout=300,
                                  env={**os.environ, 'SOL_SUDO_TMPDIR': scratch, 'LC_ALL': 'C'})
            leftovers = sorted(os.listdir(scratch))
        out = proc.stdout.decode(errors='replace')
        m = re.search(rf'^group {group}: (\d+) assertions passed$', out, re.M)
        case(f'fixture:{group}', proc.returncode == 0 and m is not None and 'no skipped fixtures' in out and not leftovers,
             f'exit={proc.returncode} leftovers={leftovers} stderr={proc.stderr.decode(errors="replace")[-2000:]}')
        if m:
            cases[-1]['assertions'] = int(m.group(1))

    # Independent oracle for the request digest: little-endian integers,
    # counted strings and the literal NUL-packed argv and environment, as the
    # wire format specifies. Expected blobs are spelled out here, not echoed.
    with tempfile.TemporaryDirectory(prefix='sol-sudo-digest-') as scratch:
        scratch = os.path.realpath(scratch)
        proc = subprocess.run([str(fixture), '--dump-request'], cwd=scratch, capture_output=True, text=True,
                              timeout=60, env={**os.environ, 'SOL_SUDO_TMPDIR': scratch})
    ok = proc.returncode == 0
    if ok:
        r = json.loads(proc.stdout.strip().splitlines()[-1])
        argv = b'/bin/echo\0x y\0\0'
        env = (b'BASHOS_CALLER_SAFE=caller\0BASHOS_CALLER_LD_PRELOAD=caller\0'
               b'BASHOS_CALLER_BASH_ENV=caller\0BASHOS_INLINE_Z=1\0')
        want = dict(mode=1, flags=2, non_interactive=1, caller_uid=os.getuid(), caller_gid=os.getgid(),
                    target_uid=4242, target_gid=4545, argc=3, envc=4, caller_user=str(os.getuid()),
                    target_user='fixture', cwd=scratch)
        fields_ok = all(r[k] == v for k, v in want.items())
        blobs_ok = bytes.fromhex(r['argv']) == argv and bytes.fromhex(r['env']) == env
        values = [r['mode'], r['flags'], r['non_interactive'], r['caller_uid'], r['caller_gid'], r['target_uid'],
                  r['target_gid'], r['argc'], r['envc'], len(argv), len(env)]
        blob = b'bashos-privcmd-v' + struct.pack('<11I', *values)
        for text in [r['caller_user'], r['target_user'], r['cwd']]:
            blob += struct.pack('<I', len(text.encode())) + text.encode()
        digest_ok = hashlib.sha256(blob + argv + env).hexdigest() == r['digest']
        ok = fields_ok and blobs_ok and digest_ok
        case('oracle:request-digest', ok, f'fields={fields_ok} blobs={blobs_ok} digest={digest_ok} {r}')
    else:
        case('oracle:request-digest', False, proc.stderr[-2000:])

if a.shell:
    if os.geteuid() == 0 or Path('/dev/bashos-auth').exists():
        case('native', False, 'native fallback checks need a non-root host without /dev/bashos-auth')
    else:
        shell = a.shell.resolve()
        with tempfile.TemporaryDirectory(prefix='sol-sudo-native-') as tmp:
            tmp = Path(tmp)
            log = tmp / 'delegate.log'
            delegate = '''#!/usr/bin/python3
import json, os, sys
fds = []
for fd in range(3, 1024):
    try: os.fstat(fd); fds.append(fd)
    except OSError: pass
row = {'name': os.path.basename(sys.argv[0]), 'argv': sys.argv[1:], 'fds': fds}
if 'FRESH' in os.environ: row['fresh'] = os.environ['FRESH']
with open(os.environ['DELEGATE_LOG'], 'a') as f:
    f.write(json.dumps(row) + '\\n')
sys.exit(int(os.environ.get('DELEGATE_EXIT', '0')))
'''
            bindir = tmp / 'bin'
            bindir.mkdir()
            for path in [tmp / 'explicit', bindir / 'doas']:
                path.write_text(delegate)
                path.chmod(0o700)

            def run(script, rc=0, extra=None, path=''):
                log.write_text('')
                env = {'HOME': str(tmp), 'LC_ALL': 'C', 'DELEGATE_LOG': str(log), **(extra or {})}
                # Exported: execvp resolves through bash's getenv, which sees
                # only exported variables.
                proc = subprocess.run([str(shell), '--noprofile', '--norc', '-c', f'export PATH={path}; ' + script],
                                      env=env, capture_output=True, timeout=120)
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                return proc.returncode == rc, proc, rows

            ok, proc, _ = run('type -t sudo doas su')
            case('native:builtins-with-empty-path', ok and proc.stdout == b'builtin\nbuiltin\nbuiltin\n', repr(proc.stdout))
            # Usage errors are decided before any delegate runs.
            for words in ['--invalid-fixture-option', '-nE /bin/true', '-K /bin/true', '-v /bin/true', '-s -i',
                          '-is', '-e -s /tmp/x', 'A=1', '-u', '--preserve-env=PATH /bin/true', '-l']:
                ok, proc, rows = run(f'sudo {words}', 2, {'BASHSUDO_EXTERNAL': str(tmp / 'explicit')})
                case(f'native:usage:{words}', ok and not rows and proc.stderr and not proc.stdout,
                     f'rc={proc.returncode} rows={rows} err={proc.stderr!r}')
            # An explicit delegate receives the original words; FDs are closed.
            script = ('exec 200</dev/null; sudo -nu root -- /bin/echo "literal ; $(printf no)" ""; '
                      'sudo -nk A=1 /bin/echo again; [[ -r /proc/$$/fd/200 ]]')
            ok, proc, rows = run(script, 0, {'BASHSUDO_EXTERNAL': str(tmp / 'explicit')})
            case('native:explicit-delegate-verbatim',
                 ok and rows == [dict(name='explicit', argv=['-nu', 'root', '--', '/bin/echo', 'literal ; no', ''], fds=[]),
                                 dict(name='explicit', argv=['-nk', 'A=1', '/bin/echo', 'again'], fds=[])],
                 f'rc={proc.returncode} rows={rows} err={proc.stderr!r}')
            # A variable exported just before the call reaches the delegate.
            ok, proc, rows = run('export FRESH=now; sudo -n /bin/true; FRESH=later; sudo -n /bin/true; '
                                 'FRESH=temp sudo -n /bin/true', 0, {'BASHSUDO_EXTERNAL': str(tmp / 'explicit')})
            case('native:delegate-sees-current-exports', ok and [r.get('fresh') for r in rows] == ['now', 'later', 'temp'],
                 f'rc={proc.returncode} rows={rows} err={proc.stderr!r}')
            ok, proc, rows = run('sudo -n /bin/true', 1, {'BASHDOAS_EXTERNAL': str(tmp / 'explicit'), 'DELEGATE_EXIT': '1'})
            case('native:delegate-denial-status', ok and len(rows) == 1, f'rc={proc.returncode} rows={rows}')
            # The default doas delegate gets doas syntax, or a refusal.
            translations = [
                ('sudo -nu nobody /bin/echo -x ""', ['-n', '-u', 'nobody', '--', '/bin/echo', '-x', '']),
                ('sudo /bin/true', ['-u', 'root', '--', '/bin/true']),
                ('sudo -su "#65534"', ['-u', '65534', '-s']),
                ('sudo -k', ['-L']),
                ('sudo -K', ['-L']),
            ]
            for script, argv in translations:
                ok, proc, rows = run(script, 0, path=str(bindir))
                case(f'native:translate:{script}', ok and rows == [dict(name='doas', argv=argv, fds=[])],
                     f'rc={proc.returncode} rows={rows} err={proc.stderr!r}')
            for script in ['sudo -i', 'sudo -e /tmp/x', 'sudo -v', 'sudo -g 0 /bin/true', 'sudo -k /bin/true',
                           'sudo A=1 /bin/true', 'sudo -s /bin/true']:
                ok, proc, rows = run(script, 1, path=str(bindir))
                case(f'native:refuse:{script}', ok and not rows and b'requires the bash-os authority' in proc.stderr,
                     f'rc={proc.returncode} rows={rows} err={proc.stderr!r}')
            ok, proc, rows = run('sudo -n /bin/true', 127)
            case('native:default-delegate-absent-with-empty-path', ok and b'external doas: doas' in proc.stderr,
                 f'rc={proc.returncode} err={proc.stderr!r}')
            # Output failures report and recover in the same shell.
            ok, proc, _ = run('sudo --version >/dev/full; a=$?; sudo -h >/dev/full; b=$?; sudo --version; echo "$a$b"')
            case('native:output-failure-recovers', ok and proc.stdout == b'sudo 0.1\n11\n', repr(proc.stdout))
            # Repeated translated calls on one CPU keep job statuses and the CHLD trap.
            cpu = min(os.sched_getaffinity(0))
            script = r'''trap ':' CHLD
saved=$(trap -p CHLD)
for ((i=0;i<300;i++)); do
  (exit 41) & bg=$!
  sudo -nu nobody /bin/true; rc=$?
  [[ $rc == 37 ]] || { echo "round $i status $rc"; exit 90; }
  wait "$bg"; [[ $? == 41 ]] || exit 91
  sudo -k; [[ $? == 37 ]] || exit 92
  [[ $(trap -p CHLD) == "$saved" ]] || exit 93
done'''
            quick = tmp / 'quick'
            quick.mkdir()
            (quick / 'doas').write_text('#!/bin/sh\nexit 37\n')
            (quick / 'doas').chmod(0o700)
            proc = subprocess.run([str(shell), '--noprofile', '--norc', '-c', f'export PATH={quick}\n' + script],
                                  env={'LC_ALL': 'C'}, capture_output=True, timeout=300,
                                  preexec_fn=lambda: os.sched_setaffinity(0, {cpu}))
            case('native:300-pinned-translated-rounds', proc.returncode == 0 and not proc.stdout and not proc.stderr,
                 f'rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}')

failed = [c for c in cases if c['status'] != 'pass']
if a.report:
    a.report.write_text(json.dumps(dict(cases=cases, failed=len(failed), total=len(cases)), indent=2) + '\n')
print(f'sol-sudo checks: {len(cases) - len(failed)}/{len(cases)} passed; live authority qualification is unavailable on this host')
raise SystemExit(1 if failed else 0)
