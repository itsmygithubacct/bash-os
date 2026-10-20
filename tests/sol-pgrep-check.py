#!/usr/bin/env python3
"""Production /proc fixtures and owned-child parity; never signals other processes.
Usage: python3 tests/sol-pgrep-check.py out/bash-sol-pgrep
No compilation is performed by this test.
"""
import ctypes
import grp
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time

BINARY = str(Path(sys.argv[1]).resolve())
ENV = dict(os.environ, PATH='', LC_ALL='C')
ENV.pop('BASHOS_PROC_ROOT', None)
checks = 0


def run(script, root=None):
    env = ENV.copy()
    if root is not None:
        env['BASHOS_PROC_ROOT'] = str(root)
    return subprocess.run([BINARY, '--noprofile', '--norc', '-c', script],
                          env=env, capture_output=True, text=True, timeout=30)


def check(args, expected, status=0, root=None, command='pgrep'):
    global checks
    p = run(shlex.join([command, *args]), root)
    assert (p.returncode, p.stdout) == (status, expected), (command, args, p.returncode, p.stdout, p.stderr, expected)
    checks += 1
    return p


def pids(args, expected, root):
    global checks
    p = run(shlex.join(['pgrep', *args]), root)
    assert p.returncode == (0 if expected else 1), (args, p.returncode, p.stderr)
    assert set(p.stdout.split()) == set(map(str, expected)), (args, p.stdout, expected)
    checks += 1


def entry(root, pid, name, args, ruid=1001, euid=2001, gid=3001,
          parent=40, group=50, session=60, start=100):
    d = root / str(pid)
    d.mkdir()
    (d/'comm').write_text(name+'\n')
    (d/'cmdline').write_bytes(b'\0'.join(a.encode() for a in args)+ (b'\0' if args else b''))
    # Uid/Gid occur after 512 bytes to catch short status-buffer assumptions.
    (d/'status').write_text('Name:\t'+name+'\n'+'Padding:\t'+'z'*600+'\n'+
        f'Uid:\t{ruid}\t{euid}\t{euid}\t{euid}\nGid:\t{gid}\t{gid+1}\t{gid}\t{gid}\n')
    fields = [parent, group, session]+[0]*15+[start]+[0]*8
    (d/'stat').write_text(f'{pid} ({name}) S '+' '.join(map(str, fields))+'\n')
    return d


with tempfile.TemporaryDirectory(prefix='sol-pgrep-') as tmp:
    root = Path(tmp)
    entry(root, 810001, 'alpha1', ['alpha1', '--mode', 'fast'], start=200)
    entry(root, 810002, 'beta22', ['/bin/beta22', 'worker'], ruid=1002, euid=2002, gid=3002,
          parent=41, group=51, session=61, start=100)
    entry(root, 810003, 'alphaXYZ', ['alphaXYZ', 'space arg'], ruid=1001, euid=2002, gid=3002, start=300)
    entry(root, 810004, 'a.b', ['a.b', 'literal'], parent=41, start=300)
    entry(root, 810005, 'kernel', [], start=50)
    entry(root, 810006, 'odd ) name', ['odd', 'arg'], parent=99, session=88, start=400)
    entry(root, 810007, 'longargs', ['longargs', 'x'*18000, 'TAIL-END'], start=500)
    good = set(range(810001, 810008))
    for args, expected in [
        (['alpha[[:digit:]]+'], {810001}),
        (['alpha.*'], {810001,810003}),
        (['-x','alpha|beta22'], {810002}),
        (['-x','alpha.*|beta22'], {810001,810002,810003}),
        (['-x',r'a\.b'], {810004}),
        (['-x','a.b'], {810004}),
        (['^beta[0-9]{2}$'], {810002}),
        (['-x',''], set()),
        ([''], good),
        (['-f','--','--mode fast$'], {810001}),
        (['-fx','alpha1 --mode fast'], {810001}),
        (['-f','TAIL-END$'], {810007}),
        (['-f','^$'], set()),
        (['-u','2001'], {810001,810004,810005,810006,810007}),
        (['-U1001'], good-{810002}),
        (['--group=3002'], {810002,810003}),
        (['-P','41'], {810002,810004}),
        (['-s60'], good-{810002,810006}),
        (['-s88'], {810006}),
        (['--pgroup','51'], {810002}),
        (['-u2001,2002','-G3002','-P40,41'], {810002,810003}),
        (['-fu2002','alpha'], {810003}),
        (['-v','alpha'], good-{810001,810003}),
        (['-v','-u2001','alpha'], good-{810001}),
        (['-n','alpha.*|a.b'], {810004}),
        (['-o','alpha.*|a.b'], {810001}),
        (['--newest','-P40'], {810007}),
        (['--oldest','-P40'], {810005}),
        (['-n','nomatch'], set()),
    ]:
        pids(args, expected, root)
    check(['-c','alpha'], '2\n', root=root)
    check(['-c','nomatch'], '0\n', 1, root)
    check(['-nc','alpha'], '1\n', root=root)
    check(['-l','-x','alpha[0-9]+'], '810001 alpha1\n', root=root)
    check(['-af','^alpha1 '], '810001 alpha1 --mode fast\n', root=root)
    check(['-a','longargs'], '810007 longargs '+'x'*18000+' TAIL-END\n', root=root)
    check(['-o','alphaXYZ|a.b'], '810003\n', root=root)
    check(['-n','alphaXYZ|a.b'], '810004\n', root=root)
    check(['-la','-x','a.b'], '810004 a.b literal\n', root=root)
    check(['-al','-x','a.b'], '810004 a.b\n', root=root)
    for delimargs, sep in [(['-d,'], ','), (['--delimiter=::'], '::'), (['-d',''], '')]:
        p = run(shlex.join(['pgrep', *delimargs, 'alpha']), root)
        expected = [f'810001{sep}810003\n', f'810003{sep}810001\n']
        assert p.returncode == 0 and p.stdout in expected, (delimargs, p.stdout)
        checks += 1
    for args in [[], ['['], ['-x','['], ['-f','('], ['\\'], ['a','b'], ['--bad'], ['-u'],
                 ['-u',''], ['-G','3001,'], ['-P','-1'], ['-s','a'], ['-U','999999999999999999999999'],
                 ['-u','missing-sol-pgrep-user'], ['-G','missing-sol-pgrep-group'],
                 ['-n','-o','a'], ['-nv','a'], ['-d'], ['-P','1,,2'],
                 ['-u',','.join(['2001']*257)]]:
        check(args, '', 2, root)
    # Invalid regex is diagnosed even with an unreadable proc tree or no records.
    check(['['], '', 2, root/'absent')
    check(['alpha'], '', 3, root/'absent')
    check(['--','-x'], '', 1, root)
    entry(root, 810021, 'axb', ['axb'])
    pids(['-x','a.b'], {810004,810021}, root)
    pids(['-x',r'a\.b'], {810004}, root)
    entry(root, 810022, 'aa', ['aa'])
    pids([r'(a)\1'], {810022}, root)
    entry(root, 810023, 'multiline', ['multiline', 'line1\nline2'])
    check(['-fx','multiline line1 line2'], '810023\n', root=root)
    check(['-a','multiline'], '810023 multiline line1 line2\n', root=root)
    # Named selectors and zero aliases use actual caller attributes.
    entry(root, 810008, 'owned', ['owned'], ruid=os.getuid(), euid=os.geteuid(), gid=os.getgid(),
          group=os.getpgrp(), session=os.getsid(0))
    pids(['-u',pwd.getpwuid(os.geteuid()).pw_name,'-U',pwd.getpwuid(os.getuid()).pw_name,
          '-G',grp.getgrgid(os.getgid()).gr_name,'-g0','-s0','owned'], {810008}, root)
    # Missing, malformed and overflowing directory records must never become PIDs.
    (root/'810009').mkdir()  # process disappears before its files can be opened
    (root/'810010').symlink_to(root/'gone', target_is_directory=True)
    (root/'214748364800000').mkdir()
    (root/'810001junk').mkdir()
    bad = entry(root, 810011, 'badids', ['badids'])
    (bad/'status').write_text('Uid:\t-1 2001 0 0\nGid:\t3001 3001 3001 3001\n')
    badstat = entry(root, 810012, 'badstat', ['badstat'])
    (badstat/'stat').write_text('810012 (badstat) S 40junk 50 60\n')
    check(['-u2001','badids'], '', 1, root)
    check(['-s60','badstat'], '', 1, root)
    check(['-n','badstat'], '', 1, root)
    pids(['alpha[0-9]+'], {810001}, root)
    # The fixture guard remains absolute for all three signal companions.
    for cmd, args in [('pkill',['-USR1','alpha.*']), ('killall',['a.b']), ('killall5',['-TERM'])]:
        p = check(args, '', 3, root, cmd)
        assert 'read-only' in p.stderr
    check(['['], '', 2, root, 'pkill')
    check(['-4294967306','alpha'], '', 2, root, 'pkill')
    check(['-0','alpha'], '', 3, root, 'pkill')
    # killall names remain literal ("[" must not be compiled as a regex).
    check(['['], '', 3, root, 'killall')
    # killall5 dry-run still respects session, empty cmdline and omit lists.
    p = run('killall5 -n -o 810001,810002', root)
    expected={str(pid) for pid,sid in [(810003,60),(810004,60),(810006,88),(810007,60),
                                         (810021,60),(810022,60),(810023,60),(810011,60)] if sid != os.getsid(0)}
    assert p.returncode == (0 if expected else 2) and set(p.stdout.split()) == expected, (p,expected)
    checks += 1
    # An already-open cmdline survives directory removal without stale state.
    # FIFO synchronization ensures the removal happens while production read blocks.
    raced = root/'810020'
    raced.mkdir()
    os.mkfifo(raced/'cmdline')
    env = dict(ENV, BASHOS_PROC_ROOT=str(root))
    child = subprocess.Popen([BINARY, '-c', "pgrep -f '^vanishing$'"], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    writer = os.open(raced/'cmdline', os.O_WRONLY)  # waits for the actual reader
    (raced/'cmdline').unlink()
    raced.rmdir()
    os.write(writer, b'vanishing\0')
    os.close(writer)
    out, err = child.communicate(timeout=10)
    assert (child.returncode, out) == (0, '810020\n'), (child.returncode, out, err)
    checks += 1
    # Self exclusion uses the actual Bash PID, even with a matching fixture entry.
    child = subprocess.Popen([BINARY, '-c', 'printf "%s\n" "$$"; read -r ready; pgrep -x self-fixture'],
                             env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    selfpid = int(child.stdout.readline())
    entry(root, selfpid, 'self-fixture', ['self-fixture'])
    child.stdin.write('ready\n'); child.stdin.flush()
    out, err = child.communicate(timeout=10)
    assert (child.returncode, out) == (1, ''), (child.returncode, out, err)
    checks += 1
    # One persistent shell: regex failures, selector changes and stdout errors reset.
    script = '''
base=(/proc/$$/fd/*)
for ((i=0;i<400;i++)); do
  pgrep '[' >/dev/null 2>&1; [[ $? == 2 ]] || exit 11
  pgrep -c -x 'alpha[[:digit:]]+' || exit 12
  pgrep -u2002 -G3002 -c alpha || exit 13
  pgrep -fc 'TAIL-END$' || exit 17
done
pgrep alpha >/dev/full 2>/dev/null; [[ $? == 3 ]] || exit 14
pgrep -x 'alpha[0-9]+' || exit 15
after=(/proc/$$/fd/*)
[[ ${#base[@]} == ${#after[@]} ]] || exit 16
'''
    p = run(script, root)
    assert (p.returncode,p.stdout) == (0,'1\n1\n1\n'*400+'810001\n'), (p.returncode,p.stdout[-200:],p.stderr)
    checks += 1

# All live queries and signals are restricted to direct children created below.
children=[]
code='''import ctypes,signal,sys,time
ctypes.CDLL(None).prctl(15,sys.argv[1].encode(),0,0,0)
signal.signal(signal.SIGUSR1, lambda *_: print("USR1", flush=True))
print("READY",flush=True)
while True: signal.pause()
'''
try:
    stem=f'sp{os.getpid():x}'
    names=[stem+'a.b',stem+'axb',stem+'[x]']
    for name in names:
        child=subprocess.Popen([sys.executable,'-u','-c',code,name], stdout=subprocess.PIPE, text=True)
        children.append(child)
        assert child.stdout.readline() == 'READY\n'
        time.sleep(.03)  # put starts in distinct scheduler ticks
    own=set(str(c.pid) for c in children)
    for args in [[], ['-c'], ['-l'], ['-a'], ['-n'], ['-o'], ['-u',str(os.geteuid())],
                 ['-U',str(os.getuid()),'-G',str(os.getgid())], ['-g',str(os.getpgrp())],
                 ['-s',str(os.getsid(0))], ['-f']]:
        argv=[*args,'-P',str(os.getpid()),stem+'.*']
        built=run(shlex.join(['pgrep',*argv]))
        ref=subprocess.run(['/usr/bin/pgrep',*argv],env=ENV,capture_output=True,text=True,check=False)
        assert (built.returncode,sorted(built.stdout.splitlines())) == (ref.returncode,sorted(ref.stdout.splitlines())), (argv,built,ref)
        if '-c' not in args:
            assert set(re.findall(r'(?m)^([0-9]+)(?: |$)', built.stdout)) <= own
        checks += 1
    p=run(shlex.join(['pkill','-0','-c','-P',str(os.getpid()),stem+'.*']))
    assert (p.returncode,p.stdout) == (0,'3\n'), p
    checks += 1
    # Exact regex anchors alternatives as a group, and pkill consumes the same ERE.
    pattern=stem+r'a\.b|'+stem+r'\[x\]'
    p=run(shlex.join(['pkill','-USR1','-c','-P',str(os.getpid()),'-x',pattern]))
    assert (p.returncode,p.stdout) == (0,'2\n'), p
    for i in (0,2):
        assert select.select([children[i].stdout],[],[],3)[0]
        assert children[i].stdout.readline() == 'USR1\n'
    assert not select.select([children[1].stdout],[],[],.05)[0]
    checks += 1
    # killall must keep literal matching; a regex interpretation would hit child 1 too.
    p=run(shlex.join(['killall','-USR1','-u',str(os.getuid()),names[0],names[2]]))
    assert p.returncode == 0, p
    for i in (0,2):
        assert select.select([children[i].stdout],[],[],3)[0]
        assert children[i].stdout.readline() == 'USR1\n'
    assert not select.select([children[1].stdout],[],[],.05)[0]
    checks += 1
    p=run(shlex.join(['pkill','-USR1','-P',str(os.getpid()),'-x',stem+'nomatch']))
    assert (p.returncode,p.stdout) == (1,''), p
    checks += 1
finally:
    for child in children:
        child.terminate()
    for child in children:
        child.wait(timeout=5)
print(f'PASS: {checks} fixture, persistent-shell and owned-child checks')
