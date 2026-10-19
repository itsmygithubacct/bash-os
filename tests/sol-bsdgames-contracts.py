#!/usr/bin/env python3
"""Focused bsdgames byte parity, persistent streams and headless contracts.

Does not compile. BASH_ENV/LD_PRELOAD may load an instrumented production DSO.
"""
import argparse
import os
from pathlib import Path
import select
import subprocess
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    args = ap.parse_args()
    binary = str(args.binary.resolve())
    env = {**os.environ, 'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    if os.environ.get('BSDGAMES_LOAD_ENV'):
        env.update(BASH_ENV=os.environ['BSDGAMES_LOAD_ENV'],
                   LD_PRELOAD=os.environ['BSDGAMES_ASAN_LIB'],
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    checks = 0

    def shell(script, data=b'', rc=0):
        nonlocal checks
        p = subprocess.run([binary, '--noprofile', '--norc', '-c', script],
                           input=data, capture_output=True, env=env, timeout=15)
        assert p.returncode == rc, (script, p.returncode, p.stdout[:500], p.stderr)
        assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
        checks += 1
        return p.stdout

    def expected(data, shift=13):
        table = bytes((c + shift - 65) % 26 + 65 if 65 <= c <= 90 else
                      (c + shift - 97) % 26 + 97 if 97 <= c <= 122 else c
                      for c in range(256))
        return data.translate(table)

    with tempfile.TemporaryDirectory(prefix='sol-bsdgames-test-') as tmp:
        root = Path(tmp)
        env['BASH_BSDGAMES_STATE_ROOT'] = str(root/'state')
        assert shell('type -t bsdgames') == b'builtin\n'
        fixtures = [b'', b'A', b'Az Nn\n', b'Az Nn', b'\n\n', bytes(range(256)),
                    b'\0A\xffz\r\nB\0', b'AbZz09' * 400000,
                    b'A\n' * 100000, b'a' * 65535 + b'Z\0\n',
                    b'a' * 65536 + b'N', b'a' * 65537 + b'\n']
        for data in fixtures:
            reference = subprocess.run(['/usr/bin/tr', 'A-Za-z', 'N-ZA-Mn-za-m'],
                                       input=data, capture_output=True, env=env, check=True).stdout
            assert reference == expected(data)
            (root/'input').write_bytes(data)
            for cmd, want in [('rot13', reference), ('caesar -29', expected(data, -29)),
                              ('caesar 0', data), ('caesar 52', data)]:
                assert shell(f'bsdgames {cmd}', data) == want, (cmd, len(data), 'pipe')
                assert shell(f'bsdgames {cmd} < "{root}/input"') == want, (cmd, len(data), 'file')
        (root/'a').write_bytes(b'A\0z\n')
        (root/'b').write_bytes(b'B\xffY')
        assert shell(f'''for ((i=0;i<10;i++)); do
bsdgames rot13 < "{root}/a" || exit
bsdgames rot13 < /dev/null || exit
bsdgames rot13 < "{root}/b" || exit
done''') == (b'N\0m\nO\xffL' * 10)
        # A previous fgets reader has buffered the remainder of this same FILE.
        assert shell('bsdgames number; bsdgames rot13', b'42\nAbZ\0x\xff\n') == b'forty two\nNoM\0k\xff\n'
        assert shell('bsdgames rot13; bsdgames rot13', b'Hello') == b'Uryyb'
        assert shell("bsdgames number > /dev/null <<< $'42\\nSTALE'; bsdgames rot13 <<< fresh") == b'serfu\n'
        # Early quit leaves bytes in stdio's buffer, even without setting EOF.
        (root/'early').write_bytes(b'quit\nSTALE\n')
        for source in ['early', 'same-inode']:
            (root/'same-inode').write_bytes(b'quit\nSTALE\n')
            assert shell(f'bsdgames adventure < "{root}/{source}" > /dev/null; bsdgames rot13 < "{root}/{source}"') == b'dhvg\nFGNYR\n'
        assert shell(f'bsdgames adventure < "{root}/early" > /dev/null; bsdgames rot13 < "{root}/a"') == b'N\0m\n'
        assert shell(f'bsdgames number > /dev/null; bsdgames rot13 < "{root}/a"', b'42\nSTALE\n') == b'N\0m\n'
        assert shell(f'bsdgames adventure < "{root}/early" > /dev/null; bsdgames rot13', b'fresh\n') == b'serfu\n'
        # Sequential readers of the same regular open-file description retain
        # the unread input at its logical position, including across a Bash read.
        (root/'shared').write_bytes(b'42\nAbZ\0x\xff\n')
        assert shell(f'exec < "{root}/shared"; bsdgames number; bsdgames rot13') == b'forty two\nNoM\0k\xff\n'
        assert shell(f'exec < "{root}/shared"; bsdgames number > /dev/null; IFS= read -r line; printf "%s" "$line"') == b'AbZx\xff'

        assert shell("bsdgames rot13 Hello World; bsdgames caesar -1 AbZ") == b'Uryyb Jbeyq\nZaY\n'
        assert shell("printf before; bsdgames rot13 Ab; printf after") == b'beforeNo\nafter'
        assert shell(f'printf before; bsdgames rot13 < "{root}/a"; printf after') == b'beforeN\0m\nafter'
        shell('bsdgames', rc=2)
        shell('bsdgames no-such-game', rc=2)
        shell('bsdgames info no-such-game', rc=1)
        shell('bsdgames number 12x', rc=1)
        shell('bsdgames primes 20 2', rc=1)
        shell('bsdgames wump --seed invalid', rc=2)
        shell('bsdgames adventure --invalid', rc=2)
        # Explicit bounded numeric oracle, independent of the production primality loop.
        primes = [n for n in range(2, 101) if all(n % d for d in range(2, n))]
        assert shell('bsdgames primes 2 100') == b''.join(f'{n}\n'.encode() for n in primes)
        assert shell('bsdgames morse; bsdgames morse', b'sos\n') == b'... --- ... /\n'
        (root/'morse').write_bytes(b'SOS\n')
        assert shell(f'bsdgames morse < "{root}/morse"; bsdgames morse < "{root}/morse"') == b'... --- ... /\n' * 2
        # Action contracts exercise state changes, parser rejection and EOF, not just --selftest.
        walk = b'enter building\ntake keys\ninventory\nxyzzy\nlook\nxyzzy\ndrop keys\ninventory\nquit\n'
        (root/'walk').write_bytes(walk)
        adv = shell(f'bsdgames adventure < "{root}/walk"; bsdgames adventure < "{root}/walk"')
        half = len(adv)//2
        assert adv[:half] == adv[half:] and adv.count(b'You are standing at the end of a road') == 2
        assert adv.count(b'set of keys') >= 2 and b'debris' in adv.lower(), adv
        assert b"You're not carrying anything." in adv, adv
        wump = shell('bsdgames wump --seed 42', b'!\nq\n')
        assert b'20 rooms' in wump and b"I don't understand!" in wump, wump
        assert wump.count(b'You are in room') == 2, wump
        (root/'wump').write_bytes(b'!\nq\n')
        assert shell(f'bsdgames wump --seed 42 < "{root}/wump"; bsdgames wump --seed 42 < "{root}/wump"') == wump*2
        # Read failure, buffered and immediate output failures, followed by healthy work.
        shell('bsdgames rot13 < .', rc=1)
        for command in ['bsdgames rot13', 'bsdgames rot13 hello', 'bsdgames caesar 7 hello']:
            assert shell(f'{command} > /dev/full; s=$?; [[ $s != 0 ]] || exit 9; bsdgames rot13 ok', b'hello\n') == b'bx\n'
        shell(f'bsdgames rot13 < "{root}/a" > /dev/full', rc=1)
        shell(f'bsdgames rot13 < "{root}/input" > /dev/full', rc=1)
        assert shell('bsdgames rot13 <&-; [[ $? != 0 ]]', rc=0) == b''
        assert shell('bsdgames rot13 >&-; [[ $? != 0 ]]', b'abc') == b''
        # All descriptors opened by these invocations must be released.
        shell(f'''before=(/proc/$$/fd/*)
for ((i=0;i<100;i++)); do bsdgames rot13 < "{root}/a" > /dev/null || exit; done
after=(/proc/$$/fd/*); [[ ${{#before[@]}} == ${{#after[@]}} ]]''')
        # A line must emerge while the producer still holds its pipe open.
        proc = subprocess.Popen([binary, '--noprofile', '--norc', '-c', 'bsdgames rot13'],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            proc.stdin.write(b'Hello\n'); proc.stdin.flush()
            assert select.select([proc.stdout], [], [], 3)[0], 'filter held a pipe line until EOF'
            assert os.read(proc.stdout.fileno(), 6) == b'Uryyb\n'
            proc.stdin.close()
            assert proc.wait(timeout=5) == 0, proc.stderr.read()
            checks += 1
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait()
            proc.stdout.close(); proc.stderr.close()
        master, slave = os.openpty()
        proc = subprocess.Popen([binary, '--noprofile', '--norc', '-c', 'bsdgames rot13'],
                                stdin=subprocess.PIPE, stdout=slave, stderr=subprocess.PIPE, env=env)
        os.close(slave)
        try:
            proc.stdin.write(b'Az\n'); proc.stdin.flush()
            assert select.select([master], [], [], 3)[0], 'terminal line was held until EOF'
            assert os.read(master, 64) == b'Nm\r\n'
            proc.stdin.close()
            assert proc.wait(timeout=5) == 0, proc.stderr.read()
            checks += 1
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait()
            os.close(master); proc.stderr.close()
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            proc = subprocess.run([binary, '--noprofile', '--norc', '-c', "trap '' PIPE; bsdgames rot13"],
                                  input=b'A' * 131072, stdout=write_fd, stderr=subprocess.PIPE, env=env, timeout=10)
            assert proc.returncode == 1 and b'write error' in proc.stderr, proc.stderr
            checks += 1
        finally:
            os.close(write_fd)
        assert not (root/'state').exists(), 'tested games unexpectedly wrote persistent state'
    print(f'sol-bsdgames: {checks} checks passed (GNU tr byte parity, empty PATH, persistent streams, games, errors)')


if __name__ == '__main__':
    main()
