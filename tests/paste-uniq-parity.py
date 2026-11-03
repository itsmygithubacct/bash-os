#!/usr/bin/env python3
"""Compare record framing and grouping with GNU tools; check shell output failures."""
from pathlib import Path
import os
import pty
import random
import select
import subprocess
import sys
import tempfile
import termios

binary = str(Path(sys.argv[1] if len(sys.argv)>1 else 'out/bash').resolve())
environment = dict(os.environ, LC_ALL='C', PATH='')
prefix = 'if [[ -n ${TEXT_OUTPUT_MODULE:-} ]]; then enable -f "$TEXT_OUTPUT_MODULE" paste; enable -f "$TEXT_OUTPUT_MODULE" uniq; fi\n'
checks = 0

def builtin(tool, args, data):
    p = subprocess.run([binary, '-c', prefix+'"$@"', '_', tool, *map(str,args)],
                       input=data, capture_output=True, env=environment, timeout=20)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr,p.stderr
    return p

def compare(tool, args=(), data=b'', expected_status=None):
    global checks
    actual = builtin(tool,args,data)
    expected = subprocess.run(['/usr/bin/'+tool,*map(str,args)], input=data,
                              capture_output=True, env=environment, timeout=20)
    if expected_status is not None:
        assert expected.returncode == expected_status, (args,expected.stderr)
        assert bool(actual.stderr) == bool(expected.stderr), (args,actual.stderr,expected.stderr)
    assert (actual.returncode,actual.stdout)==(expected.returncode,expected.stdout), (
        tool,args,actual.returncode,expected.returncode,actual.stdout[:200],expected.stdout[:200],actual.stderr)
    checks += 1

with tempfile.TemporaryDirectory() as directory:
    d = Path(directory)
    first,second = d/'first',d/'second'
    def compare_paste_script(script, data=b'', expected=None):
        global checks
        results = []
        for executable, prelude in [('/bin/bash', 'paste() { /usr/bin/paste "$@"; };\n'),
                                    (binary,prefix)]:
            result = subprocess.run([executable,'-c',prelude+script,'_',str(first),str(second)],
                                    input=data,capture_output=True,env=environment,timeout=20,cwd=d)
            assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr,result.stderr
            results.append((result.returncode,result.stdout,result.stderr))
        assert results[0][0]==0 and not results[0][2],results[0]
        if expected is not None: assert results[0][1]==expected,results[0]
        assert results[1]==results[0],(script,results)
        checks += 1

    # Each shell call owns its stream, while multiple '-' operands within
    # one paste still consume a shared input in sequence.
    for zero in (False,True):
        delim = b'\0' if zero else b'\n'
        first.write_bytes(delim.join([b'a',b'b'])+delim)
        second.write_bytes(delim.join([b'c',b'd'])+delim)
        for options in ('-s','-s -','-s - -','-','- -',''):
            flags = ('-z ' if zero else '') + options
            compare_paste_script(f'paste {flags} <"$1"; paste {flags} <"$2"')
        first.write_bytes(b'')
        compare_paste_script(f'paste {"-zs" if zero else "-s"} <"$1"; '
                             f'paste {"-zs" if zero else "-s"} <"$2"',
                             expected=delim+b'c\td'+delim)
    first.write_bytes(b'a\nb\n'); second.write_bytes(b'c\nd\n')
    compare_paste_script('paste -s <"$1"; IFS= read -r line; printf "%s\\n" "$line"',
                         data=b'shell input\n',expected=b'a\tb\nshell input\n')
    for operands in ('','-','"$1" -','- "$1"'):
        for mode in ('','-s'):
            compare_paste_script(f'paste {mode} {operands} 0<&- 2>/dev/null; '
                                 'printf "status=%s\\n" "$?"; paste -s <"$2"')
    compare_paste_script('ulimit -n 48; for ((i=0; i<128; i++)); do '
                         'paste - missing <"$1" 2>/dev/null; [[ $? == 1 ]] || exit 90; '
                         'paste -s <"$1" >/dev/null || exit 91; done; paste -s <"$2"',
                         expected=b'c\td\n')
    # A failed output leaves stdio read-ahead behind unless stdin is private.
    first.write_bytes(b'old record\n'*20000)
    for mode in ('','-s'):
        compare_paste_script(f'paste {mode} <"$1" >/dev/full 2>/dev/null; '
                             'printf "status=%s\\n" "$?"; paste -s <"$2"',
                             expected=b'status=1\nc\td\n')
    # Numeric options share GNU's decimal syntax and saturating bounds. Check
    # all spellings, including legacy counts, against an independent process.
    valid_counts = ['0', '+0', '-0', '-000', '1', '+1', '  +1', '\t1', '01',
                    '2', '4294967296', '18446744073709551615',
                    '18446744073709551616', '999999999999999999999999',
                    '+' + '9' * 200, '0' * 200 + '1']
    invalid_counts = ['', ' ', '+', '-', '-1', '  -1', '-18446744073709551616',
                      '1 ', '1junk', '1K', '0x1', '++1', '+-0', '9' * 200 + 'x']
    for short,long in [('-f','--skip-fields'),('-s','--skip-chars'),('-w','--check-chars')]:
        for value in valid_counts + invalid_counts:
            valid = value in valid_counts
            for args in [[short,value],[short+value],[long,value],[long+'='+value]]:
                # An empty attached short argument means a missing operand.
                for zero in ((False,True) if valid else (False,)):
                    data = b'ax same\nbx same\nbx same\ncy other\n'
                    if zero: data = data.replace(b'\n',b'\0')
                    compare('uniq',(['-z'] if zero else [])+args,data,
                            expected_status=0 if valid else 1)
        first.write_bytes(b'preserve input\n')
        second.write_bytes(b'preserve output\n')
        compare('uniq',[short,'9'*200+'x',first,second],expected_status=1)
        assert first.read_bytes()==b'preserve input\n'
        assert second.read_bytes()==b'preserve output\n'
    for args in [['-18446744073709551616'],['-999999999999999999999999'],
                 ['-999999999999999999999999d'],['+18446744073709551616'],
                 ['-18446744073709551616','-1'],['-1','-2'],
                 ['-f','1','-2'],['-2','-f','1'],['-f','+1','-2'],
                 ['-18446744073709551616','-f','1']]:
        compare('uniq',args,b'ax same\nbx same\ncy other\n',expected_status=0)
    datasets = [b'', b'one', b'a\na\nb\nb\nc\n', b'a\0x\na\0x\na\0y',
                b'a'*65535+b'\n'+b'b'*65536+b'\n'+b'c'*65537,
                b'Alpha\nalpha\nBeta\nBETA\n',b'a 1\nb 1\nc 2\n']
    rng = random.Random(20260907)
    datasets += [b'\n'.join(rng.choice([b'',b'a',b'b',b'a\0z',b'Ab',b'AB'])
                             for _ in range(300)) for _ in range(8)]
    for data in datasets:
        for zero in (False,True):
            body = data.replace(b'\n',b'\0') if zero else data
            start = ['-z'] if zero else []
            first.write_bytes(body); second.write_bytes(body[:len(body)//2])
            for opts in [[],['-c'],['-d'],['-u'],['-i'],['-f','1'],['-s','1'],['-w','2'],
                         ['-D'],['--all-repeated=separate'],['--all-repeated=prepend'],
                         ['--group'],['--group=prepend'],['--group=append'],['--group=both']]:
                compare('uniq',start+opts,body)
            for opts in [[],['-s'],['-d',',|'],['-s','-d',r'\0,\n']]:
                compare('paste',start+opts+[first,second])
                compare('paste',start+opts+['-','-'],body)
    for tool in ('paste','uniq'):
        compare(tool,[d])  # reading a directory is an error
        compare(tool,[d/'missing'])
        first.write_bytes(b'a\na\nb\n')
        script = prefix+'''printf before
"$1" "$2"
printf after
rc=0; "$1" "$2" >/dev/full 2>/dev/null || rc=$?
[[ $rc == 1 ]] || exit 42
"$1" "$2"
'''
        p = subprocess.run([binary,'-c',script,'_',tool,str(first)],capture_output=True,env=environment,timeout=20)
        expected = b'a\na\nb\n' if tool=='paste' else b'a\nb\n'
        assert p.returncode==0 and p.stdout==b'before'+expected+b'after'+expected,(tool,p.returncode,p.stdout,p.stderr)
        checks += 1
    destination = d/'result'
    p = builtin('uniq',[first,destination],b'')
    assert p.returncode==0 and destination.read_bytes()==b'a\nb\n'
    checks += 1
    # A terminal receives complete lines while the input stream remains open.
    for tool in ('paste','uniq'):
        master,slave = pty.openpty()
        settings = termios.tcgetattr(slave)
        settings[1] &= ~termios.ONLCR
        termios.tcsetattr(slave,termios.TCSANOW,settings)
        try:
            with subprocess.Popen([binary,'-c',prefix+'"$@"','_',tool],env=environment,
                                  stdin=subprocess.PIPE,stdout=slave,stderr=subprocess.PIPE) as proc:
                proc.stdin.write(b'a\nb\n'); proc.stdin.flush()
                assert select.select([master],[],[],10)[0],(tool,'terminal output waited for EOF')
                assert os.read(master,1024).startswith(b'a\n')
                _,errors = proc.communicate(timeout=10)
                assert proc.returncode==0 and not errors,(tool,proc.returncode,errors)
        finally:
            os.close(master); os.close(slave)
        checks += 1
print(f'paste-uniq: {checks} GNU parity and output-state checks passed')
