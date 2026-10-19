#!/usr/bin/env python3
"""Owned loopback peers running genuine cluster builtins in independent shells.

No compiler or external command is run by a peer (PATH is empty). This module
also supplies the same validated fixture to bench/sol-cluster.py.
"""
import argparse
import concurrent.futures
import contextlib
import hashlib
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import time


class Peer:
    def __init__(self, binary, directory, timeout=200):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.proc = subprocess.Popen(
            [str(binary), '--noprofile', '--norc'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={'PATH': '', 'LC_ALL': 'C', 'BASHCLUSTER_STATE_DIR': str(directory),
                 'BASHCLUSTER_TIMEOUT_MS': str(timeout),
                 **{name: os.environ[name] for name in
                    ('LD_PRELOAD', 'ASAN_OPTIONS', 'UBSAN_OPTIONS') if name in os.environ}})
        self.buffer = b''
        self.sequence = 0
        self.call('PATH=; type -t cluster')
        module = os.environ.get('BASHOS_CLUSTER_TEST_MODULE')
        if module:
            self.call('enable -f ' + shlex.quote(module) + ' cluster')

    def call(self, script, rc=0, timeout=3):
        self.sequence += 1
        mark = f'__CLUSTER_RESULT_{self.sequence}__'
        command = f'{script}\nprintf "\\n{mark}:%s\\n" "$?"\n'
        self.proc.stdin.write(command.encode()); self.proc.stdin.flush()
        end = time.monotonic() + timeout
        prefix = ('\n' + mark + ':').encode()
        while True:
            at = self.buffer.find(prefix)
            if at >= 0 and b'\n' in self.buffer[at+len(prefix):]:
                line, rest = self.buffer[at+len(prefix):].split(b'\n', 1)
                out, self.buffer = self.buffer[:at], rest
                actual = int(line)
                assert actual == rc, (script, actual, rc, out.decode(errors='replace'))
                return out.decode()
            left = end - time.monotonic()
            assert left > 0, ('bounded command deadline exceeded', script, self.buffer)
            readable, _, _ = select.select([self.proc.stdout], [], [], left)
            assert readable, ('bounded command deadline exceeded', script, self.buffer)
            data = os.read(self.proc.stdout.fileno(), 65536)
            assert data, ('peer shell died', self.proc.poll(), self.buffer)
            self.buffer += data

    def command(self, *args, **kwargs):
        return self.call('cluster ' + shlex.join(map(str, args)), **kwargs)

    def status(self):
        return dict(line.split('=', 1) for line in self.command('status').splitlines())

    def members(self):
        rows = [line.split() for line in self.command('members').splitlines()]
        assert all(len(row) == 2 for row in rows), rows
        assert len({row[0] for row in rows}) == len(rows), rows
        assert len({row[1] for row in rows}) == len(rows), rows
        return dict(rows)

    def init(self):
        self.command('init', '-p', 0)
        self.info = self.status()
        assert self.info['state'] == 'initialized', self.info
        assert int(self.info['listener_pid']) != self.proc.pid
        self.endpoint = '127.0.0.1:' + self.info['port']
        return self.info

    def join(self, seed):
        self.command('join', seed.endpoint, '-k', seed.directory / 'private_key')
        self.info = self.status()
        self.endpoint = '127.0.0.1:' + self.info['port']
        assert self.info['cluster_id'] == seed.info['cluster_id'], self.info
        assert self.info['node_id'] != seed.info['node_id'], self.info

    def close(self):
        if self.proc.poll() is None:
            with contextlib.suppress(Exception):
                self.proc.stdin.write(b'cluster leave >/dev/null 2>&1\nexit\n')
                self.proc.stdin.flush()
                self.proc.wait(timeout=3)
            if self.proc.poll() is None:
                self.proc.kill(); self.proc.wait(timeout=3)
        for stream in (self.proc.stdin, self.proc.stdout):
            stream.close()


@contextlib.contextmanager
def peers(binary, root, count=3, timeout=200):
    owned = []
    try:
        for i in range(count):
            owned.append(Peer(binary, Path(root) / f'peer-{i}', timeout))
        yield owned
    finally:
        for peer in reversed(owned):
            peer.close()


def eventually(check, timeout=3):
    end = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < end, 'membership convergence deadline exceeded'
        time.sleep(.01)


def roster_is(peers, expected):
    return all(peer.members() == expected for peer in peers)


def packet(key, kind=1, count=0, node=b'1'*32, port=12345, cluster=bytes(32)):
    body = b'BCLSTR2\0' + bytes([kind, count]) + struct.pack('!H', port)
    body += bytes(range(16)) + cluster + node + bytes(32*34)
    return body + hashlib.blake2b(body, key=key, digest_size=32).digest()


def test_membership(binary):
    with tempfile.TemporaryDirectory(prefix='sol-cluster-') as tmp, peers(binary, tmp) as (a, b, c):
        assert a.status()['state'] == 'uninitialized'
        assert a.members() == {}
        a.command('--version'); a.command('--help'); a.command('leave')
        a.init()
        expected = {a.info['node_id']: a.endpoint}
        assert a.members() == expected
        inherited = [os.readlink(fd) for fd in Path('/proc',a.info['listener_pid'],'fd').iterdir()]
        assert len(inherited) == 5, inherited
        assert inherited.count('/dev/null') == 3, inherited
        assert sum(target.startswith('socket:') for target in inherited) == 1, inherited
        for name in ('private_key', 'members', 'cluster_id', 'node_id', 'port'):
            assert (a.directory / name).stat().st_mode & 0o777 == 0o600
        a.command('init', '-p', 0, rc=1)
        b.join(a)
        expected[b.info['node_id']] = b.endpoint
        eventually(lambda: roster_is((a, b), expected))
        b.command('join', a.endpoint, '-k', a.directory / 'private_key', rc=1)
        assert roster_is((a, b), expected)
        c.join(a)
        expected[c.info['node_id']] = c.endpoint
        eventually(lambda: roster_is((a, b, c), expected))
        for peer in (a, b, c):
            for node, endpoint in expected.items():
                assert peer.command('ping', node) == f'ok {node}\n'
                assert peer.command('ping', endpoint) == f'ok {endpoint}\n'
        # Repeated calls stay native and neither failures nor successful RPCs leak FDs.
        a.call('before=(/proc/$$/fd/*); for ((i=0;i<40;i++)); do '
               f'cluster ping {shlex.quote(b.endpoint)} >/dev/null || exit 71; '
               'cluster ping missing >/dev/null 2>&1 && exit 72; done; '
               'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
        a.call('cluster members >/dev/full', rc=1)
        assert a.members() == expected  # stdout error does not poison later calls
        c.command('leave')
        del expected[c.info['node_id']]
        eventually(lambda: roster_is((a, b), expected))
        assert c.status()['state'] == 'uninitialized' and c.members() == {}
        assert sorted(p.name for p in c.directory.iterdir()) == ['lock']
        c.command('leave')
        # Kill only the owned shell; its listener must close its socket and clean state.
        port = int(b.info['port'])
        b.proc.kill(); b.proc.wait(timeout=2)
        eventually(lambda: not (b.directory / 'cluster_id').exists())
        eventually(lambda: a.members() == expected_minus(expected, b.info['node_id']))
        def socket_released():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(('127.0.0.1', port))
                    return True
                except OSError:
                    return False
        eventually(socket_released)
        assert sorted(p.name for p in b.directory.iterdir()) == ['lock']
        a.command('leave')
        assert a.status()['state'] == 'uninitialized'
    print('PASS init/join/3-peer convergence/node+endpoint ping/duplicate/leave/shell death/FD+state cleanup')


def expected_minus(rows, node):
    return {key: value for key, value in rows.items() if key != node}


def test_failures(binary):
    with tempfile.TemporaryDirectory(prefix='sol-cluster-') as tmp, peers(binary, tmp) as (a, b, c):
        a.init(); original = a.members()
        wrong = Path(tmp) / 'wrong.key'; wrong.write_text('ab'*32 + '\n')
        b.command('join', a.endpoint, '-k', wrong, rc=1, timeout=1)
        assert b.status()['state'] == 'uninitialized' and b.members() == {}
        assert a.members() == original
        b.command('join', a.endpoint, rc=2)
        empty = Path(tmp) / 'empty.key'; empty.write_bytes(b'')
        b.command('join', a.endpoint, '-k', empty, rc=1)
        fifo = Path(tmp) / 'fifo.key'; os.mkfifo(fifo)
        b.command('join', a.endpoint, '-k', fifo, rc=1, timeout=1)
        b.command('join', a.endpoint, '-k', Path(tmp)/'absent.key', rc=1)
        b.call('BASHCLUSTER_TIMEOUT_MS=0 cluster status', rc=1)
        b.call('BASHCLUSTER_TIMEOUT_MS=5001 cluster status', rc=1)
        public = Path(tmp) / 'public'; public.mkdir(mode=0o755)
        public.chmod(0o755)
        b.call(f'BASHCLUSTER_STATE_DIR={shlex.quote(str(public))} cluster init -p 0', rc=1)
        b.call('BASHCLUSTER_MOCK_SSH=1 cluster ping bad:1', rc=1)
        # Descriptor and state cleanup also hold over repeated listener lifetimes.
        b.call('before=(/proc/$$/fd/*); for ((i=0;i<5;i++)); do '
               'cluster init -p 0 >/dev/null || exit 81; '
               'cluster leave >/dev/null || exit 82; done; '
               'after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]')
        assert b.status()['state'] == 'uninitialized'

        for argv in (('init','-p','-1'), ('init','-p','65536'), ('init','-p','1x'),
                     ('init','-p'), ('init','--bad'), ('join','host:12'),
                     ('join','127.0.0.1:0'), ('join','127.0.0.1:65536'),
                     ('ping',), ('ping','x','extra'), ('members','extra'),
                     ('leave','extra'), ('status','extra'), ('unknown',)):
            b.command(*argv, rc=2)
        # Owned silent UDP peer and owned non-protocol TCP peer never count as members.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(('127.0.0.1', 0))
            endpoint = f'127.0.0.1:{silent.getsockname()[1]}'
            b.command('join', endpoint, '-k', a.directory / 'private_key', rc=1, timeout=1)
            a.command('ping', endpoint, rc=1, timeout=1)
        for attempt in range(32):
            with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                tcp.bind(('127.0.0.1', 0)); tcp.listen()
                try:
                    udp.bind(tcp.getsockname())  # reserve both protocols; contact only owned ports
                except OSError:
                    continue
                b.command('join', f'127.0.0.1:{tcp.getsockname()[1]}', '-k', a.directory / 'private_key', rc=1, timeout=1)
                break
        else:
            raise AssertionError('could not reserve an owned non-protocol endpoint')
        # Bind collision must not damage existing listener or leave partial state.
        b.command('init', '-p', a.info['port'], rc=1)
        assert b.status()['state'] == 'uninitialized'
        # Malformed, truncated, oversized, wrong-key, invalid-op and signed invalid rows.
        key = bytes.fromhex((a.directory / 'private_key').read_text().strip())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.bind(('127.0.0.1', 0))
            port = sender.getsockname()[1]
            cluster = a.info['cluster_id'].encode()
            # Independent Python BLAKE2b oracle also proves a valid wire exchange.
            sender.settimeout(1)
            sender.sendto(packet(key, kind=4, port=port, cluster=cluster),
                          ('127.0.0.1', int(a.info['port'])))
            pong, address = sender.recvfrom(2048)
            assert address == ('127.0.0.1', int(a.info['port']))
            assert len(pong) == 1212 and pong[:8] == b'BCLSTR2\0' and pong[8] == 7
            assert pong[12:28] == bytes(range(16)) and pong[28:60] == cluster
            assert pong[-32:] == hashlib.blake2b(pong[:-32], key=key, digest_size=32).digest()
            valid = packet(key, port=port)
            bad = [b'', b'garbage', valid[:-1], valid+b'X', bytes(len(valid)),
                   packet(bytes([9])*32, port=port), packet(key, kind=255, port=port, cluster=cluster),
                   packet(key, count=33, port=port), packet(key, count=1, port=port),
                   packet(key, node=b'\x00'*32, port=port), packet(key, port=0),
                   packet(key, port=port, cluster=b'2'*32)]
            for data in bad:
                sender.sendto(data, ('127.0.0.1', int(a.info['port'])))
        # These commands are ordered after packet dispatch and verify responsiveness.
        assert a.command('ping', a.endpoint) == f'ok {a.endpoint}\n'
        assert a.members() == original
        b.join(a); c.join(a)
        expected = {p.info['node_id']: p.endpoint for p in (a,b,c)}
        eventually(lambda: roster_is((a,b,c), expected))
        # SIGKILL of the owned listener bypasses leave; heartbeat expiry is the oracle.
        os.kill(int(c.info['listener_pid']), signal.SIGKILL)
        eventually(lambda: roster_is((a,b), expected_minus(expected,c.info['node_id'])))
        assert c.status()['state'] == 'stopped'
        # A killed atomic writer can leave a private scratch file; recover only ours.
        (c.directory / '.members.tmp').write_text('partial')
        (c.directory / 'unrelated').write_text('keep')
        c.command('leave')  # recover stale disk state without signaling a PID from disk
        assert not (c.directory / '.members.tmp').exists()
        assert (c.directory / 'unrelated').read_text() == 'keep'
        assert c.status()['state'] == 'uninitialized'
        # Seed loss is visible to a live leaf, not a permanently stale roster.
        a.proc.kill(); a.proc.wait(timeout=2)
        eventually(lambda: b.status()['state'] == 'disconnected')
        assert b.members() == {b.info['node_id']: b.endpoint}
        b.command('ping', a.endpoint, rc=1, timeout=1)
        b.command('leave')
        c.init(); c.command('leave')  # reuse a directory after abnormal listener death
    print('PASS key mismatch/invalid input/timeout/nonprotocol/bind collision/malformed packets/expiry/seed disconnect/stale recovery')


def test_child_ownership(binary):
    with tempfile.TemporaryDirectory(prefix='sol-cluster-child-') as tmp, peers(binary, tmp, count=2) as (a,b):
        a.init()
        # The service must not inherit the guard's temporary SIGCHLD block.
        def blocked(pid):
            return next(line for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                        if line.startswith('SigBlk:'))
        assert not (int(blocked(a.info['listener_pid']).split()[1], 16) & (1 << (signal.SIGCHLD-1)))
        original_mask = blocked(b.proc.pid)
        fifo = Path(tmp)/'wake'; os.mkfifo(fifo)
        b.call(f'exec {{wake}}<> {shlex.quote(str(fifo))}; chld_count=0; '
               "trap '((chld_count+=1))' CHLD; "
               '(read -r -t 20 -u "$wake"; exit 41) & survivor=$!')
        survivor = int(b.call('printf "%s" "$survivor"'))
        trap = b.call('trap -p CHLD')
        wrong = Path(tmp)/'wrong'; wrong.write_text('ab'*32+'\n')
        for attempt in range(6):
            # This unrelated Bash job exits while the listener waits for a bad MAC.
            b.call('(read -r -t 0.02 -u "$wake"; exit 37) & completed=$!')
            b.command('join', a.endpoint, '-k', wrong, rc=1, timeout=1)
            b.call('wait "$completed"', rc=37)
            assert b.call('trap -p CHLD') == trap
            assert blocked(b.proc.pid) == original_mask
            b.call('kill -0 "$survivor"; [[ $chld_count -gt 0 ]]')
            assert b.status()['state'] == 'uninitialized'
            assert sorted(p.name for p in b.directory.iterdir()) == ['lock']
        # Persistence failure sends readiness=0 and exits immediately, racing
        # the parent's failure cleanup. A directory cannot be renamed over.
        (b.directory/'members').mkdir()
        b.command('init','-p',0,rc=1)
        (b.directory/'members').rmdir()
        # Also exercise readiness EOF before any response, with an owned child
        # killed during its real handshake. Never signal a PID from state.
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as silent:
            silent.bind(('127.0.0.1',0))
            endpoint=f'127.0.0.1:{silent.getsockname()[1]}'
            children = Path(f'/proc/{b.proc.pid}/task/{b.proc.pid}/children')
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
                pending = worker.submit(b.command, 'join', endpoint, '-k', a.directory/'private_key', rc=1)
                end = time.monotonic()+1
                while True:
                    owned = set(map(int,children.read_text().split())) - {survivor}
                    if owned:
                        assert len(owned) == 1, owned
                        os.kill(owned.pop(),signal.SIGKILL)
                        break
                    assert not pending.done() and time.monotonic() < end
                    time.sleep(.001)
                pending.result(timeout=2)
            # A forged on-disk PID must not be used by stale recovery.
            for name,value in (('listener_pid',str(survivor)),('cluster_id',a.info['cluster_id']),
                               ('node_id','1'*32),('port',str(silent.getsockname()[1]))):
                (b.directory/name).write_text(value+'\n')
            (b.directory/'private_key').write_bytes((a.directory/'private_key').read_bytes())
            b.command('leave')
        assert b.call('trap -p CHLD') == trap
        assert blocked(b.proc.pid) == original_mask
        b.call('kill -0 "$survivor"')
        b.init()
        assert b.command('ping',b.endpoint) == f'ok {b.endpoint}\n'
        assert b.call('trap -p CHLD') == trap
        b.call('kill -0 "$survivor"')
        b.command('leave')
        # Wake and reap our unrelated job normally; its original status survives.
        b.call('printf "wake\\n" >&"$wake"; wait "$survivor"',rc=41)
        b.call('[[ $chld_count -gt 0 ]]; exec {wake}>&-; trap - CHLD')
        b.init(); b.command('leave')
        eventually(lambda: not children.read_text().strip())
    print('PASS guarded failure/readiness EOF/child exit/SIGCHLD trap/unrelated jobs+statuses/masks/forged state PID')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args=parser.parse_args()
    binary=args.binary.resolve(strict=True)
    test_membership(binary)
    test_failures(binary)
    test_child_ownership(binary)
    print('sol-cluster: all real membership checks passed')


if __name__ == '__main__':
    main()
