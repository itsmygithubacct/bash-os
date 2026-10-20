#!/usr/bin/env python3
"""GNU sed dialect/cycle parity and exact shared-input consumption contracts."""
from pathlib import Path
import os
import pty
import select
import socket
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
env = dict(os.environ, PATH='', LC_ALL='C', TZ='UTC')
prefix = 'if [[ -n ${HEAD_SED_MODULE:-} ]]; then enable -f "$HEAD_SED_MODULE" sed || exit; fi\n'
checks = 0
failures = []


def run(args, data=b'', script='sed "$@"'):
    p = subprocess.run([binary, '--noprofile', '--norc', '-c', prefix+script, '_', *map(str,args)],
                       input=data, capture_output=True, env=env, timeout=15)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p


def parity(args, data=b'', error=False):
    global checks
    actual = run(args, data)
    expected = subprocess.run(['/usr/bin/sed', *map(str,args)], input=data, capture_output=True, env=env, timeout=15)
    # The builtin retains its documented 1/2 error-code convention.
    if error:
        assert actual.returncode > 0 and expected.returncode > 0, (args, actual, expected)
    else:
        if (actual.returncode,actual.stdout)!=(expected.returncode,expected.stdout):
            failure = (args, data[:100], actual.returncode, actual.stdout[:500], expected.returncode, expected.stdout[:500], actual.stderr)
            failures.append(failure)
            print('FAIL', failure, flush=True)
            return
    checks += 1


with tempfile.TemporaryDirectory(prefix='sol-sed-') as directory:
    d = Path(directory)
    files = [d/'a', d/'empty', d/'b', d/'tail']
    files[0].write_bytes(b'alpha\na+b (ab) aaab\na\0b')
    files[1].touch()
    files[2].write_bytes(b'beta\nalpha\n')
    files[3].touch()
    scripts = ['', '=', '$p', '1,4p', '4,2p', '2,$p', '0,/alpha/p', '/alpha/,/beta/p',
               '1h;$g', '1h;2,$H;$ {g;p;}', 'N', 'N;P;D', 'n;=', 'n;$p', 'N;$p',
               '/alpha/h;//p', '1s/alpha/OMEGA/;2s//X/',
               '$ {F;p;}', '1,3c changed', '/alpha/,/beta/c changed']
    for script in scripts:
        for opts in ([], ['-s']):
            parity([*opts, '-e', script, *files])
    data = b'aaab\na+b a|b\n(ab)\nab\nabb\nALPHA\nalpha\na\0b\0alpha\nlast'
    scripts = ['s/a+b/X/g', r's/a\+b/X/g', 's/(ab)/X/g', r's/\(ab\)/[\1]/g',
               r's/\(a\)\1/X/g', r's/a\{2,3\}/X/g', 's/a{2,3}/X/g',
               '/a+b/p', r'/a\+b/p', '/alpha/Ip', '/alpha/ {s//X/g;p;}',
               's/alpha/OMEGA/i;s//X/g', 's/a/X/;//p', 's/a/X/;s/z/Z/;t yes;d;:yes;p',
               's/a/X/;T next;:next;t yes;d;:yes;p',
               'N;/^b/p', 'N;/a.b/p', r'N;/a\nb/p', 'N;s/^/X/gm',
               r's/\b/X/g', r's/\</X/g', 's/./X/g', 's/b/X/g', 's/[^a]/X/g',
               's/.*$/[&]/', 's/a*/X/g', 's/b*/X/g', 's/a/X/2g', r's|a\|b|X|g', r's+a\+b+X+g']
    for script in scripts:
        for opts in ([], ['-E']):
            parity([*opts, '-n', '-e', script], data)
    # Empty regex is resolved at execution time, even when a later command
    # appears first lexically, or when the regex came from a previous file.
    for script in ('b later;s//X/;:later;/a/p', '1b end;s//X/;:end;/a/p'):
        parity([script], b'a\na\n')
    for args in (['s//X/'], ['//p'], ['s/[/X/'], ['{p'], ['b missing'],
                 ['-E','s/(/X/'], ['s/a/X/;s//Y/i'], [r's/a/\1/'], ['//Ip'], ['}'], ['p;'*16+'b missing'], ['-f', d/'missing']):
        parity(args, b'a\n', error=True)
    # The builtin rejects numbers outside its supported range before they
    # can overflow C arithmetic; GNU saturates some such values instead.
    for script in ('999999999999999999999999p', 's/a/X/9999999999999999999999',
                   'q 999999999999999999999999'):
        assert run([script], b'a\n').returncode == 1, script
        checks += 1
    assert run(['-f', d], b'a\n').returncode == 1
    checks += 1
    # Capture groups, binary subjects, multiline state and final newlines.
    for data in (b'', b'a', b'a\0b', b'a\0b\n', b'a\0b\nc\0d', b'\0\n\0'):
        for script in ('', 'p', 'h;G', 'N;P', 's/./[&]/g', r's/\(.\)/\1\1/g',
                       's/b/B/g', '/b/p', '$p', 's/[^a]/X/g', r's/\x00/X/g', r'/\x00/p', r's/./\x00/g', r's/b/\o000/g', r's/a/\d000/g'):
            parity([script], data)
    # Named control escapes must produce the same bytes as numeric escapes,
    # including inside a case-converting or capture-bearing replacement.
    for escape in ('r', 'a', 'f', 'v', 'n', 't'):
        for replacement in ('\\'+escape, r'\U'+'\\'+escape+r'&\E', r'\1'+'\\'+escape):
            parity([r's/\(a\)/'+replacement+'/g'], b'a\0a\n')
    old_locale = env['LC_ALL']
    env['LC_ALL'] = 'C.UTF-8'
    for script in ('s/x*/-/g', 's/./[&]/g', r's/\b/-/g', 's/é/X/g'):
        parity([script], 'éあ é\n'.encode())
    env['LC_ALL'] = old_locale
    # Separate-file and in-place state, backup bytes and an empty middle file.
    for script in ('=', '$p', '1h;$g', 'N', '/alpha/,/beta/p'):
        left = [d/f'left{i}' for i in range(3)]
        right = [d/f'right{i}' for i in range(3)]
        for l,r,data in zip(left,right,[b'alpha\na\0z',b'',b'beta\nlast']):
            l.write_bytes(data); r.write_bytes(data)
        got = run(['-i.bak',script,*left])
        ref = subprocess.run(['/usr/bin/sed','-i.bak',script,*map(str,right)],capture_output=True)
        assert got.returncode == ref.returncode == 0, (script,got,ref)
        for l,r in zip(left,right):
            assert l.read_bytes()==r.read_bytes(), (script,l.read_bytes(),r.read_bytes())
            assert Path(str(l)+'.bak').read_bytes()==Path(str(r)+'.bak').read_bytes()
        checks += 1
    for data in (b'a\0b', b'a\0b\nc\0d\n'):
        actual_path,reference_path=d/'written',d/'reference'
        for command in ('w ', 'W ', 's/b/B/w '):
            actual=run(['-n',command+str(actual_path)],data)
            expected=subprocess.run(['/usr/bin/sed','-n',command+str(reference_path)],input=data,capture_output=True)
            assert actual.returncode==expected.returncode==0
            assert actual_path.read_bytes()==reference_path.read_bytes()
            checks += 1
    for script in ('q 7', 'Q 9'):
        left = [d/'quit-left0',d/'quit-left1']
        right = [d/'quit-right0',d/'quit-right1']
        for l,r in zip(left,right):
            l.write_bytes(b'a\nb\n');r.write_bytes(b'a\nb\n')
        got=run(['-i',script,*left])
        ref=subprocess.run(['/usr/bin/sed','-i',script,*map(str,right)],capture_output=True)
        assert got.returncode==ref.returncode, (got,ref)
        assert [x.read_bytes() for x in left]==[x.read_bytes() for x in right]
        checks += 1
    # Exact consumption is checked using the original pipe read end after sed
    # exits, while its producer remains open. NUL as the lookahead byte matters.
    for data in (b'a\nb\nc\n', b'a\n\0b\nc', b'a\nb'):
        for script, consumed in [('1q',2), ('1q;$p',2), ('$!q',2), ('$p;1q',2),
                                 ('1,$p;1q',2), ('n;$!q',data.index(b'\n',2)+1 if b'\n' in data[2:] else None),
                                 ('N;$!q',data.index(b'\n',2)+1 if b'\n' in data[2:] else None)]:
            if consumed is None or consumed == len(data):
                continue
            readfd,writefd = os.pipe()
            os.write(writefd,data)
            proc = subprocess.Popen([binary,'-c',prefix+'sed "$1"','_',script],stdin=readfd,
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            try:
                out,err=proc.communicate(timeout=5)
                assert proc.returncode==0, (script,proc.returncode,err)
                # No read may block: the expected suffix is already available.
                os.set_blocking(readfd,False)
                rest=os.read(readfd,65536)
                assert rest==data[consumed:], (script,data,rest,data[consumed:])
                checks += 1
            finally:
                if proc.poll() is None: proc.kill(); proc.wait()
                os.close(readfd); os.close(writefd)
    # Nonconsuming lookahead also covers sockets and releases its temporary
    # pipe descriptors on every invocation in a persistent shell.
    reader,writer=socket.socketpair()
    writer.sendall(b'a\n\0socket\n')
    try:
        got=subprocess.run([binary,'-c',prefix+"sed '$!q'"],stdin=reader,
                           capture_output=True,env=env,timeout=5)
        assert got.returncode==0 and got.stdout==b'a\n', got
        reader.setblocking(False)
        assert reader.recv(4096)==b'\0socket\n'
        checks += 1
    finally:
        reader.close();writer.close()
    readfd,writefd=os.pipe()
    os.write(writefd,b'a\n'*128+b'\0remaining\n')
    try:
        got=subprocess.run([binary,'-c',prefix+"ulimit -n 32; for ((i=0;i<128;i++)); do sed '$!q' >/dev/null || exit; done"],
                           stdin=readfd,capture_output=True,env=env,timeout=10)
        assert got.returncode==0, got
        os.set_blocking(readfd,False)
        assert os.read(readfd,4096)==b'\0remaining\n'
        checks += 1
    finally:
        os.close(readfd);os.close(writefd)
    # Seekable stdin returns all stdio read-ahead, including dollar lookahead.
    shared = d/'shared'
    for script, consumed in [('$p;1q', 2), ('n;$!q', 4), ('N;$!q', 4)]:
        shared.write_bytes(b'a\nb\nc\n')
        with shared.open('rb', buffering=0) as stream:
            proc = subprocess.run([binary,'-c',prefix+'sed "$1"','_',script],stdin=stream,
                                  capture_output=True,env=env,timeout=5)
            assert proc.returncode==0 and stream.tell()==consumed, (script,proc,stream.tell())
            assert stream.read()==b'a\nb\nc\n'[consumed:]
            checks += 1
    # Looking past the last line of a file into '-' cannot consume stdin.
    one = d/'one'; one.write_bytes(b'one\n')
    readfd,writefd=os.pipe()
    os.write(writefd,b'\0next\n')
    proc=subprocess.Popen([binary,'-c',prefix+'sed "$@"','_', '$p;1q',str(one),'-'],
                          stdin=readfd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    try:
        out,err=proc.communicate(timeout=5)
        assert proc.returncode==0 and out==b'one\n', (out,err)
        os.set_blocking(readfd,False)
        assert os.read(readfd,65536)==b'\0next\n'
        checks += 1
    finally:
        if proc.poll() is None: proc.kill();proc.wait()
        os.close(readfd);os.close(writefd)
    # $ before q must await either the next byte or real EOF, then preserve
    # that next byte. q before an unevaluated $ has no such dependency.
    for script in ('$p;1q', '$!q'):
        readfd,writefd=os.pipe()
        proc=subprocess.Popen([binary,'-c',prefix+'sed "$1"','_',script],stdin=readfd,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:
            os.write(writefd,b'a\n')
            assert not select.select([proc.stdout],[],[],0.15)[0], (script,'treated live pipe as EOF')
            os.write(writefd,b'\0tail\n')
            out,err=proc.communicate(timeout=5)
            assert proc.returncode==0 and out==b'a\n', (script,out,err)
            os.set_blocking(readfd,False)
            assert os.read(readfd,65536)==b'\0tail\n'
            checks += 1
        finally:
            if proc.poll() is None: proc.kill(); proc.wait()
            os.close(readfd); os.close(writefd)
    # EOF after the complete line makes $ true, and no extra record appears.
    for script in ('$p;q', '$!q'):
        parity([script],b'a\n')
    # Repeated errors, early lookahead quits and normal calls cannot retain
    # regex, range, hold, output-error state or descriptors in one shell.
    got=run([files[0]],script='''ulimit -n 32
for ((i=0;i<128;i++)); do
  sed 's//X/' < "$1" >/dev/null 2>/dev/null && exit 41
  sed '/[/' < "$1" >/dev/null 2>/dev/null && exit 42
  sed p < "$1" >/dev/full 2>/dev/null && exit 43
  sed '$!q' < "$1" >/dev/null || exit
  sed '1h;$g' < "$1" >/dev/null || exit
done
sed -n '$p' < "$1"''')
    assert got.returncode==0 and got.stdout==b'a\0b', got
    checks += 1
    # A read/open error cannot be hidden by a later file or q success.
    for bad in (d, d/'missing'):
        got=run([bad,files[0]],script='sed q "$@" >/dev/null 2>/dev/null; rc=$?; [[ $rc != 0 ]]')
        assert got.returncode==0, got
        checks += 1
    # Terminal output must arrive before an open producer sends another line.
    master,slave=pty.openpty()
    proc=subprocess.Popen([binary,'-c',prefix+'sed s/a/A/'],stdin=subprocess.PIPE,
                          stdout=slave,stderr=subprocess.PIPE,env=env)
    try:
        os.close(slave)
        proc.stdin.write(b'a\n');proc.stdin.flush()
        assert select.select([master],[],[],5)[0]
        assert os.read(master,4096)==b'A\r\n'
        assert proc.poll() is None
        proc.stdin.close();proc.stdin=None
        out,err=proc.communicate(timeout=5)
        assert proc.returncode==0, err
        checks += 1
    finally:
        if proc.poll() is None: proc.kill();proc.wait()
        os.close(master)
assert not failures, f'{len(failures)} GNU parity failures (details above)'
print(f'sol-sed: {checks} GNU byte/cycle, exact-consumption and recovery checks passed')
