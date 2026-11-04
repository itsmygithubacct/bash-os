#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only regression: deterministic sock_diag and proc TCP state labels."""
import argparse
import importlib.util
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('fixtures', Path(__file__).with_name('sol-netstat-behavior.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

NETSTAT = ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2',
           'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'CLOSING', 'UNKNOWN')
SS = ('ESTAB', 'SYN-SENT', 'SYN-RECV', 'FIN-WAIT-1', 'FIN-WAIT-2',
      'TIME-WAIT', 'UNCONN', 'CLOSE-WAIT', 'LAST-ACK', 'LISTEN', 'CLOSING', 'UNKNOWN')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    args = parser.parse_args()
    binary, shim = args.binary.resolve(), args.shim.resolve()
    with tempfile.TemporaryDirectory(prefix='netstat-tcp-labels-') as tmp:
        base = f.fixtures(Path(tmp) / 'fixture')
        states = list(range(1, 12)) + [12]
        for family, name in ((2, 'tcp'), (10, 'tcp6')):
            (base / 'proc/net' / name).write_text('header\n' + ''.join(
                f.proc_row(i, family, state, 41000 + i, 42000 + i)
                for i, state in enumerate(states)))
            (base / 'diag' / f'{family}-6.bin').write_bytes(b''.join(
                f.inet(family, state, 41000 + i, 42000 + i)
                for i, state in enumerate(states)) + f.msg(kind=3))
        for transport in ('diag', 'proc'):
            env = f.environment(shim, base, transport)
            for command, expected in (('netstat -tna', NETSTAT), ('ss -tna', SS)):
                result = f.run(binary, command, env)
                assert result.returncode == 0, (transport, command, result.stderr)
                lines = [line.split() for line in result.stdout.splitlines()[1:]]
                for proto in ('tcp', 'tcp6'):
                    actual = [line[5 if command.startswith('netstat') else 1]
                              for line in lines if line[0] == proto]
                    assert actual == list(expected), (transport, command, proto, actual)
            result = f.run(binary, 'netstat -una', env)
            assert result.returncode == 0, (transport, result.stderr)
            assert [line.split()[5] for line in result.stdout.splitlines()[1:]] == ['UNCONN', 'ESTAB'], (transport, result.stdout)
            print(f'PASS {transport}: TCP IPv4/IPv6, ss and UDP state labels')


if __name__ == '__main__':
    main()
