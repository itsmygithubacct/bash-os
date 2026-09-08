#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check tac record boundaries, binary data, repeated calls and write failures."""
import argparse
import errno
import os
from pathlib import Path
import pty
import random
import subprocess
import tempfile
import termios


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', nargs='?', default='out/bash')
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve(strict=True))
    reference = '/usr/bin/tac'
    environment = {'PATH':'', 'LC_ALL':'C', 'TZ':'UTC', 'TERM':'dumb'}
    for name in ['TAC_MODULE','ASAN_OPTIONS','UBSAN_OPTIONS','QEMU_CPU','QEMU_LD_PREFIX']:
        if name in os.environ:
            environment[name] = os.environ[name]
    prefix = 'if [[ -n ${TAC_MODULE:-} ]]; then enable -f "$TAC_MODULE" tac || exit; fi\n'
    checks = 0

    def run(command, data=b'', script='"$@"', **kwargs):
        result = subprocess.run([binary,'--noprofile','--norc','-c',prefix+script,
                                 '_',*map(str,command)], input=data, env=environment,
                                stdout=kwargs.pop('stdout',subprocess.PIPE),
                                stderr=subprocess.PIPE, timeout=20, **kwargs)
        assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr, result.stderr
        return result

    def compare(options=(), data=b'', script='"$@"'):
        nonlocal checks
        actual = run(['tac',*options],data,script)
        expected = run([reference,*options],data,script)
        assert (actual.returncode,actual.stdout)==(expected.returncode,expected.stdout), (
            options, data[:100], actual.returncode, expected.returncode,
            actual.stdout[:200],expected.stdout[:200],actual.stderr)
        checks += 1

    with tempfile.TemporaryDirectory(prefix='bash-os-tac-test-') as directory:
        root = Path(directory)
        first, second = root/'first', root/'second'
        # Boundaries at the output buffer edge, records longer than the input
        # block, binary separators, adjacent separators and overlapping matches.
        datasets = [b'',b'a',b'\n',b'\n\n',b'a\nb\nc',b'a\nb\nc\n',
                    b'\na\n\nb\n',b'ababa',b'aaaaaaa',b'::a::::b::tail',
                    b'a\0b\0\0c\nlast',b'\xff\xfe\0x\n\x80tail',
                    'one\n\u00e9\n\u754c'.encode(),
                    b'a'*65535+b'\n'+b'b'*65536+b'\n'+b'c'*65537,
                    b'X\n'*65536,b'no separator '*10000]
        for data in datasets:
            first.write_bytes(data)
            for sep in ['\n','aba','aa','::','', 'separator longer than a short input']:
                for before in [False,True]:
                    options = (['-b'] if before else [])+['-s',sep]
                    compare(options,data)
                    compare([*options,first])
        rng = random.Random(20260908)
        for _ in range(80):
            data = bytes(rng.choice(b'aaab\n\0:|') for _ in range(rng.randrange(2048)))
            sep = rng.choice(['a','aa','aba','::','|','\n',''])
            compare(['-s',sep],data)
            compare(['--before','--separator='+sep],data)

        first.write_bytes(b'first\na\nlast')
        second.write_bytes(b'second\nb\n')
        dash = root/'-file'; dash.write_bytes(b'option\noperand')
        for options in [[],['-b'],['-s','a'],['-s','']]:
            compare([*options,first,second])
            compare([*options,first,'-',second,'-'],b'pipe\ninput\n')
            compare([*options,'-','-'],b'pipe\ninput\n')
            compare([*options,'--',dash])
        compare([root])
        compare([root/'missing',first])
        compare([first,root/'missing',second])
        compare([],b'a\nb\n',script='printf "before:"; "$@"; printf ":after"')

        # Common patterns only: this loadable retains POSIX extended regex
        # syntax, which is not the complete GNU tac regex dialect.
        for data in [b'a,b:c',b',a,,b:',b'a\nb\nlast',b'abc']:
            for pattern in ['[,:]','\n']:
                compare(['-r','-s',pattern],data)
                compare(['-b','-r','-s',pattern],data)
        for options in [['-s'],['--bad-option'],['-r','-s','[']]:
            actual,expected = run(['tac',*options],b'x'),run([reference,*options],b'x')
            assert actual.returncode and expected.returncode,(options,actual.returncode,expected.returncode)
            checks += 1

        # Each redirection is reopened in one persistent shell, with a Bash
        # read after tac to check that shell input remains usable.
        first.write_bytes(b'a\nb\nc\n'); second.write_bytes(b'next\nvalue')
        script = '''tool=$1; first=$2; second=$3
for ((i=0;i<3;i++)); do
  "$tool" < "$first" || exit
  "$tool" -s t < "$second" || exit
  "$tool" < /dev/null || exit
  IFS= read -r line < "$second" || exit
  printf '<%s>' "$line"
done
'''
        actual = run(['tac',first,second],script=script)
        expected = run([reference,first,second],script=script)
        assert (actual.returncode,actual.stdout)==(0,expected.stdout),(actual.returncode,actual.stdout,expected.stdout,actual.stderr)
        checks += 1
        compare([],b'a\nb\nc\n',script='for ((i=0;i<3;i++)); do printf "a\\nb\\nc\\n" | "$@" || exit; done')

        # Stock head can leave unread bytes in Bash's stdin FILE. A later
        # tac must read its new descriptor, just as an external command does.
        # The core/full profiles include head; an exact tac-only build does not.
        if run([],script='[[ $(type -t head) == builtin ]]').returncode == 0:
            first.write_bytes(b'first\nleftover\n'); second.write_bytes(b'new\ninput\n')
            script = 'head -n1 < "$2" || exit; "$1" < "$3"'
            actual = run(['tac',first,second],script=script)
            expected = run([reference,first,second],script=script)
            assert expected.returncode == 0 and (actual.returncode,actual.stdout)==(0,expected.stdout), (
                actual.returncode,actual.stdout,expected.stdout,actual.stderr)
            checks += 1
        else:
            print('SKIP stdin read-ahead regression: this selection has no head builtin')

        for size in [3,65535,65536,65537,200000]:
            first.write_bytes((b'a\nb\n'*((size+3)//4))[:size])
            expected = run([reference,first]).stdout
            for destination in ['/dev/full','closed']:
                redirect = '>/dev/full' if destination=='/dev/full' else '1>&-'
                script = f'''tac "$1" {redirect} 2>/dev/null
rc=$?
[[ $rc == 1 ]] || exit 42
printf 'alive:'
tac "$1"
'''
                actual = run([first],script=script)
                assert actual.returncode==0 and actual.stdout==b'alive:'+expected,(size,destination,actual.returncode,actual.stdout[:100],actual.stderr)
                checks += 1

        # An ignored SIGPIPE becomes a checked EPIPE; it must not be reported
        # as success, nor leave the shell unable to continue.
        read_fd,write_fd = os.pipe(); os.close(read_fd)
        try:
            result = run([],b'a\nb\n',script="trap '' PIPE; tac; rc=$?; [[ $rc == 1 ]]",stdout=write_fd)
            assert result.returncode==0,(result.returncode,result.stderr)
            checks += 1
        finally:
            os.close(write_fd)

        master,slave = pty.openpty()
        settings = termios.tcgetattr(slave); settings[1] &= ~termios.ONLCR
        termios.tcsetattr(slave,termios.TCSANOW,settings)
        try:
            result = run(['tac'],b'a\nb\nc',script='printf before; "$@"; printf after',stdout=slave)
            os.close(slave); slave = -1
            output = b''
            while True:
                try:
                    chunk = os.read(master,4096)
                except OSError as error:
                    if error.errno!=errno.EIO: raise
                    break
                if not chunk: break
                output += chunk
            assert result.returncode==0 and output==b'beforecb\na\nafter',(result.returncode,output,result.stderr)
            checks += 1
        finally:
            os.close(master)
            if slave!=-1: os.close(slave)
    print(f'tac: {checks} reference parity and shell-state checks passed')


if __name__=='__main__':
    main()
