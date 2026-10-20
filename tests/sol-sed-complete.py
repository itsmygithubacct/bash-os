#!/usr/bin/env python3
"""GNU byte, framing, terminal-consumption and CLI regression checks for sed."""
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import termios
import tty

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
checks = failures = 0

def check(label, actual, expected):
    global checks, failures
    checks += 1
    if actual != expected:
        failures += 1
        print('FAIL', label, repr(actual)[:600], 'expected', repr(expected)[:600], flush=True)

def run(args, data=b'', reference=False):
    cmd = ['/usr/bin/sed', *map(str, args)] if reference else [binary, '-c', 'sed "$@"', '_', *map(str, args)]
    p = subprocess.run(cmd, input=data, capture_output=True, env=env, timeout=10)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p.returncode, p.stdout

def parity(args, data=b''):
    check((args, data[:30]), run(args, data), run(args, data, True))

with tempfile.TemporaryDirectory(prefix='sol-sed-complete-') as tmp:
    d = Path(tmp)
    for data in (b'', b'a', b'\0', b'a\0b', b'a\nb', b'a\n'):
        for script in ('q', 'q 7', 'p;q', '-n', 'a tail\nq', 'Q', 'p;Q'):
            if script == '-n': parity(['-n', 'p;q'], data)
            else: parity([script], data)
    for width in (0, 1, 2, 4, 69, 70, 71):
        for data in (b'a'*70, b'a'*69+b'\t\0\\', b'\t'+b'a'*75, bytes(range(1,256))):
            parity(['-n', f'l {width}'], data)
            parity(['-n', '-l', str(width), 'l'], data)
    for n in (68,69,70,71,139,140): parity(['-n', 'l'], b'a'*n)
    for aux in (b'tail', b'\0tail', b'a\nb', b'a\nb\n', b''):
        f = d/'aux'; f.write_bytes(aux)
        for op in ('r', 'R'):
            for script in (f'{op} {f}', f'{op} {f}\nq', f'{op} {f}\nd', f'{op} {f}\nN', f'{op} {f}\nn', f'{op} {f}\na end'):
                for data in (b'a', b'a\nb\nc\n'):
                    parity([script], data)
    for data in (b'a\0b\0b\n', bytes(range(256)), b'\0\0\n', b'abc'):
        for script in (r's/\(\x00b\)/[\1]/g', r's/[\x00]/X/g', r's/[^\x00]/X/g',
                       's/./[&]/g', r's/\(.\)\1/X/g', r's/\b/-/g', r's/\B/-/g',
                       r's/\x00\|b/X/g', r'/\x00/p', 'N;s/^/!/gm', 's/.*$/X/'):
            parity([script], data)
    for args in (['-es/a/A/'], ['--expression=s/a/A/'], ['--quiet', 'p'],
                 ['-u', 'p'], ['--unbuffered', 'p'], ['--regexp-extended', 's/a+/X/'],
                 ['--separate', '='], ['--line-length=4','l'], ['-nl4', 'l'],
                 ['--bad-option'], [], ['-e'], ['-f'], ['p', d/'missing'],
                 ['p',d], ['-f',d/'missing']):
        parity(args, b'aaa\n')
    f=d/'script'
    f.write_text('#'+ 'x'*4093+'\ns/a/A/\n')
    for args in (['-f',f], ['-f'+str(f)], ['--file='+str(f)]):parity(args,b'a\n')
    for data in (b'', b'a\n'):
        for script in ('w '+str(d/'missing/out'), 's/z/Z/w '+str(d/'missing/out')):
            parity([script], data)
    for args in (['-i','p',d/'missing'], ['-i','p'], ['-i','p',d]): parity(args)
    good=d/'good';good.write_bytes(b'good\n')
    parity(['p',d,good])
    parity(['p',d/'missing',good])
    # Empty write destinations are opened and truncated at invocation start.
    left,right=d/'left-write',d/'right-write'
    for data in (b'',b'a\n'):
        left.write_bytes(b'old');right.write_bytes(b'old')
        actual=run(['s/z/Z/w '+str(left)],data)
        expected=run(['s/z/Z/w '+str(right)],data,True)
        check('unreached write',(actual,left.read_bytes()),(expected,right.read_bytes()))
    f.write_bytes(b'')
    parity(['-f',f], b'a\0b\n')
    # Private PTY; both canonical and raw input retain every lookahead byte.
    for raw in (False,True):
        for suffix in (b'b\nc\n', b'\0b\n'):
            master,slave=pty.openpty()
            attrs=termios.tcgetattr(slave); attrs[3] &= ~termios.ECHO
            termios.tcsetattr(slave,termios.TCSANOW,attrs)
            if raw: tty.setraw(slave)
            p=subprocess.Popen([binary,'-c',"sed '$!q'"],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            try:
                os.write(master,b'a\n'+suffix)
                out,err=p.communicate(timeout=5)
                check(('tty output',raw,suffix),(p.returncode,out),(0,b'a\n'))
                os.set_blocking(slave,False)
                rest=b''
                while select.select([slave],[],[],0)[0]:
                    rest+=os.read(slave,4096)
                check(('tty suffix',raw,suffix),rest,suffix)
            finally:
                if p.poll() is None:p.kill();p.wait()
                os.close(master);os.close(slave)
    # A canonical EOF marker must let dollar finish while the PTY stays open.
    master,slave=pty.openpty()
    p=subprocess.Popen([binary,'-c',"sed -n '$p'"],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    try:
        os.write(master,b'a\n\x04')
        out,err=p.communicate(timeout=5)
        check('tty EOF',(p.returncode,out),(0,b'a\n'))
    finally:
        if p.poll() is None:p.kill();p.wait()
        os.close(master);os.close(slave)
print(f'sol-sed-complete: {checks} checks, {failures} failures',flush=True)
raise SystemExit(bool(failures))
