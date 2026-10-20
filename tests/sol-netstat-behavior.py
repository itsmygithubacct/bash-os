#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned sockets plus independent proc/sock_diag fixture oracles.

No compilation occurs here. Build the syscall shim separately through the build
 gate. Every case is retained in JSON, including failures; unmatched host rows
are never counted as a fixture or used as expected output.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = 'Proto Recv-Q Send-Q Local Address               Foreign Address             State'

def row(proto, recv, send, local, peer, state, owner=''):
    return f'{proto:<5} {recv:<6} {send:<6} {local:<26} {peer:<26} {state}{owner}\n'

def msg(payload=b'', kind=20, seq=0, flags=0):
    n = 16 + len(payload)
    return struct.pack('=IHHII', n, kind, flags, seq, 0) + payload + bytes((-n) % 4)

def inet(family, state, port, peerport=0, inode=101, recv=3, send=5, seq=0):
    addr = socket.inet_pton(family, '127.0.0.1' if family == 2 else '::1')
    addr = addr.ljust(16, b'\0')
    peer = addr if peerport else bytes(16)
    body = struct.pack('=BBBB', family, state, 0, 0)
    body += struct.pack('!HH', port, peerport) + addr + peer
    body += struct.pack('=III', 0, 0xffffffff, 0xffffffff)
    body += struct.pack('=IIIII', 0, recv, send, 1000, inode)
    assert len(body) == 72
    return msg(body, seq=seq)

def unix(state, path, inode=301):
    body = struct.pack('=BBBBIII', 1, 1, state, 0, inode, 0xffffffff, 0xffffffff)
    data = path.encode() + b'\0'
    attr = struct.pack('=HH', 4 + len(data), 0) + data
    body += attr + bytes((-len(attr)) % 4)
    return msg(body)

def proc_addr(family, address, port):
    packed = socket.inet_pton(family, address)
    words = struct.unpack('=' + 'I' * (len(packed)//4), packed)
    return ''.join(f'{x:08X}' for x in words) + f':{port:04X}'

def proc_row(index, family, state, port, peerport=0, inode=101, recv=3, send=5):
    local = proc_addr(family, '127.0.0.1' if family == 2 else '::1', port)
    peer = proc_addr(family, ('127.0.0.1' if family == 2 else '::1') if peerport else ('0.0.0.0' if family == 2 else '::'), peerport)
    return f'{index}: {local} {peer} {state:02X} {send:08X}:{recv:08X} 00:00000000 00000000 1000 0 {inode}\n'

def fixtures(base, large=0):
    base = Path(base)
    (base/'proc/net').mkdir(parents=True)
    (base/'diag').mkdir()
    for pid in ('4242', '9999'):
        (base/f'proc/{pid}/fd').mkdir(parents=True)
        (base/f'proc/{pid}/comm').write_text('fixture\n')
    for fd, ino in ((7,101),(8,201),(9,301)):
        (base/f'proc/4242/fd/{fd}').symlink_to(f'socket:[{ino}]')
    tables = {
        'tcp': proc_row(0,2,10,41001) + proc_row(1,2,1,41002,41003,102),
        'tcp6': proc_row(0,10,10,42001,inode=111),
        'udp': proc_row(0,2,7,43001,inode=201) + proc_row(1,2,1,43002,43003,202),
        'udp6': '',
        'unix': '0000: 00000002 00000000 00010000 0001 01 301 /fixture/listener\n'
                '0000: 00000002 00000000 00000000 0001 03 302 /fixture/connected\n',
    }
    if large:
        tables['tcp'] = ''.join(proc_row(i,2,10 if i%3==0 else 1,10000+i,0 if i%3==0 else 60000,1000+i) for i in range(large))
        tables['tcp6'] = ''
    for name, data in tables.items():
        (base/f'proc/net/{name}').write_text('fixture header\n' + data)
    diag = {
        '2-6': inet(2,10,41001) + inet(2,1,41002,41003,102),
        '10-6': inet(10,10,42001,inode=111),
        '2-17': inet(2,7,43001,inode=201) + inet(2,1,43002,43003,202),
        '10-17': b'',
        '1-0': unix(10,'/fixture/listener') + unix(1,'/fixture/connected',302),
    }
    for name, data in diag.items():
        (base/f'diag/{name}.bin').write_bytes(data + msg(kind=3))
    return base

def expected_inet(proto='tcp', listen=False, large=0):
    if large:
        return ''.join(row('tcp',3,5,f'127.0.0.1:{10000+i}', '0.0.0.0:*' if i%3==0 else '127.0.0.1:60000', 'LISTEN' if i%3==0 else 'ESTAB') for i in range(large) if not listen or i%3==0)
    if proto == 'tcp':
        return row('tcp',3,5,'127.0.0.1:41001','0.0.0.0:*','LISTEN') + ('' if listen else row('tcp',3,5,'127.0.0.1:41002','127.0.0.1:41003','ESTAB')) + row('tcp6',3,5,'::1:42001',':::*','LISTEN')
    return row('udp',3,5,'127.0.0.1:43001','0.0.0.0:*','UNCONN') + ('' if listen else row('udp',3,5,'127.0.0.1:43002','127.0.0.1:43003','ESTAB'))

def environment(shim=None, fixture=None, transport=None):
    env = dict(os.environ, PATH='', LC_ALL='C')
    if shim:
        env['LD_PRELOAD'] = (env['LD_PRELOAD'] + ':' if env.get('LD_PRELOAD') else '') + str(shim)
    if fixture:
        env.update(SOL_NETSTAT_FIXTURE=str(fixture), SOL_NETSTAT_TRANSPORT=transport or 'proc')
    return env

def run(binary, script, env):
    return subprocess.run([str(binary),'--noprofile','--norc','-c',script], env=env, capture_output=True, text=True, timeout=30)

class Suite:
    def __init__(self, binary, shim):
        self.binary, self.shim, self.results = binary, shim, []
    def case(self, name, fn):
        try:
            fn()
        except Exception as e:
            self.results.append(dict(name=name,status='fail',error=str(e)))
            print('FAIL',name,str(e),flush=True)
        else:
            self.results.append(dict(name=name,status='pass'))
            print('PASS',name,flush=True)
    def check(self, script, env, output=None, code=0):
        r = run(self.binary, script, env)
        assert r.returncode == code, (r.returncode,r.stdout,r.stderr)
        assert 'runtime error:' not in r.stderr and 'AddressSanitizer' not in r.stderr,r.stderr
        if output is not None:
            assert r.stdout == output, f'expected {output[:1500]!r}; got {r.stdout[:1500]!r}; stderr={r.stderr!r}'
        return r

    def fixture_cases(self, base):
        for transport in ('diag','proc'):
            env = environment(self.shim,base,transport)
            for opts, expect in (
                ('-tna',expected_inet()),
                ('--tcp --numeric --all',expected_inet()),
                ('-tnl',expected_inet(listen=True)),
                ('--tcp --numeric --listening',expected_inet(listen=True)),
                ('-una',expected_inet('udp')),
                ('--udp --numeric --all',expected_inet('udp')),
                ('-unl',expected_inet('udp',True)),
                ('--udp --listening',expected_inet('udp',True)),
                ('-xnl',row('u_str',0,0,'/fixture/listener','*','LISTEN')),
                ('--unix --listening',row('u_str',0,0,'/fixture/listener','*','LISTEN')),
                ('-xna',row('u_str',0,0,'/fixture/listener','*','LISTEN')+row('u_str',0,0,'/fixture/connected','*','ESTAB')),
            ):
                self.case(f'{transport} {opts}',lambda opts=opts,expect=expect,env=env:self.check('netstat '+opts,env,HEADER+'\n'+expect))
            combined=HEADER+'\n'+expected_inet()+expected_inet('udp')+row('u_str',0,0,'/fixture/listener','*','LISTEN')+row('u_str',0,0,'/fixture/connected','*','ESTAB')
            self.case(f'{transport} default families',lambda env=env,combined=combined:self.check('netstat',env,combined))
            self.case(f'{transport} combined families',lambda env=env,combined=combined:self.check('netstat -tuxan',env,combined))
            self.case(f'{transport} option state resets',lambda env=env:self.check('netstat -tna; netstat -una',env,HEADER+'\n'+expected_inet()+HEADER+'\n'+expected_inet('udp')))
            def ownership(env=env):
                r = self.check('netstat --tcp --listening --programs',env)
                assert r.stdout.splitlines()[0] == HEADER+'        PID/Program',r.stdout
                line = next(x for x in r.stdout.splitlines() if '127.0.0.1:41001' in x)
                assert line.endswith(' users:(("fixture",pid=4242,fd=7))'),line
                assert '9999' not in r.stdout,r.stdout
            self.case(f'{transport} -p ownership and denied fd dir',ownership)
            self.case(f'{transport} repeated calls and output recovery',lambda env=env:self.check(
                'netstat -tnl >/dev/full; a=$?; netstat -tnl >/dev/null; b=$?; netstat --version >/dev/full; c=$?; netstat -tnl >/dev/null; d=$?; printf "%s %s %s %s\\n" "$a" "$b" "$c" "$d"', env, '1 0 1 0\n'))
            self.case(f'{transport} exact output after failed write',lambda env=env:self.check('netstat -tnl >/dev/full; s=$?; netstat -tna; printf "<status>%s\\n" "$s"',env,HEADER+'\n'+expected_inet()+'<status>1\n'))
            self.case(f'{transport} FD cleanup 100 calls',lambda env=env:self.fd_cleanup(env))
        self.case('both transports and tables denied return failure',lambda:self.check('netstat -ta',environment(self.shim,base,'denied'),code=1))
        for arg in ('--bogus','-z','operand','-','--tcp=bad','--','-tZ'):
            self.case('invalid '+arg,lambda arg=arg:self.check('netstat '+shlex.quote(arg),environment(),output='',code=2))
        for arg in ('--help','-h','--version'):
            self.case('informational '+arg,lambda arg=arg:self.check('netstat '+arg,environment()))

    def fd_cleanup(self, env):
        p = subprocess.Popen([str(self.binary),'--noprofile','--norc','-c',
            'printf "ready\\n"; read -r x; for ((i=0;i<100;i++)); do netstat -anp >/dev/null || exit; done; printf "done\\n"; read -r x'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        try:
            assert p.stdout.readline() == 'ready\n'
            before = set(os.listdir(f'/proc/{p.pid}/fd'))
            p.stdin.write('go\n'); p.stdin.flush()
            assert p.stdout.readline() == 'done\n',p.stderr.read()
            after = set(os.listdir(f'/proc/{p.pid}/fd'))
            assert after == before,(before,after)
            p.stdin.write('quit\n');p.stdin.flush()
            assert p.wait(timeout=10) == 0
        finally:
            if p.poll() is None: p.kill(); p.wait()

    def malformed(self, tmp):
        # Each mutation drives the production reader, not a duplicate parser.
        variants = {
            'short inet payload':msg(b'\x02'),
            'short NLMSG_ERROR':msg(b'',kind=2),
            'bad netlink length':struct.pack('=IHHII',1000,20,0,0,0)+b'x',
            'mismatched seq':inet(2,1,55555,55556,seq=0xffffffff),
            'short Unix payload':msg(b'\x01'),
            'interrupted dump':inet(2,10,41001)+msg(kind=3,flags=16),
            'DONE error payload':msg(struct.pack('=i',-13),kind=3),
        }
        for name, data in variants.items():
            base=fixtures(Path(tmp)/name.replace(' ','-'))
            target='1-0' if 'Unix' in name else '2-6'
            (base/f'diag/{target}.bin').write_bytes(data+msg(kind=3))
            def check(base=base,target=target,name=name):
                r=self.check('netstat -xna' if target=='1-0' else 'netstat -tna',environment(self.shim,base,'diag'))
                assert '55555' not in r.stdout,r.stdout
                if name=='mismatched seq': assert r.stdout==HEADER+'\n'+row('tcp6',3,5,'::1:42001',':::*','LISTEN'),r.stdout
                else:
                    expected = (row('u_str',0,0,'/fixture/listener','*','LISTEN')+row('u_str',0,0,'/fixture/connected','*','ESTAB')) if target=='1-0' else expected_inet()
                    assert r.stdout==HEADER+'\n'+expected,r.stdout
            self.case('malformed '+name,check)
        base=fixtures(Path(tmp)/'invalid-unix-attr')
        payload=struct.pack('=BBBBIII',1,1,10,0,301,0xffffffff,0xffffffff)+struct.pack('=HH',3,0)
        (base/'diag/1-0.bin').write_bytes(msg(payload)+msg(kind=3))
        self.case('malformed Unix attribute falls back',lambda:self.check('netstat -xnl',environment(self.shim,base,'diag'),HEADER+'\n'+row('u_str',0,0,'/fixture/listener','*','LISTEN')))
        base=fixtures(Path(tmp)/'malformed-proc')
        bad='not a socket row\n0: Z:1 Z:2 01 0:0 0:0 0 1000 0 555\n0: 1:1 1:2 01 0:0 0:0 0 1000 0 556\n'
        (base/'proc/net/tcp').write_text('header\n'+bad+proc_row(1,2,1,41002,41003,102))
        (base/'proc/net/tcp6').write_text('header\n0: x:1 x:2 01 0:0 0:0 0 1000 0 557\n')
        self.case('malformed proc rows skipped',lambda:self.check('netstat -tna',environment(self.shim,base,'proc'),HEADER+'\n'+row('tcp',3,5,'127.0.0.1:41002','127.0.0.1:41003','ESTAB')))
        base=fixtures(Path(tmp)/'partial-error')
        (base/'diag/2-6.bin').write_bytes(inet(2,10,41001)+msg(struct.pack('=i',-13)+bytes(16),kind=2))
        self.case('partial netlink failure has no duplicate rows',lambda:self.check('netstat -tna',environment(self.shim,base,'diag'),HEADER+'\n'+expected_inet()))

    def live(self, tmp):
        with contextlib.ExitStack() as stack:
            def sock(fam,typ):return stack.enter_context(socket.socket(fam,typ))
            sockets=[]
            for family,addr in ((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')):
                listener=sock(family,socket.SOCK_STREAM);listener.bind((addr,0));listener.listen(8)
                client=sock(family,socket.SOCK_STREAM);client.connect(listener.getsockname())
                server=stack.enter_context(listener.accept()[0])
                udp=sock(family,socket.SOCK_DGRAM);udp.bind((addr,0))
                peer=sock(family,socket.SOCK_DGRAM);peer.bind((addr,0));peer.connect(udp.getsockname())
                sockets += [(listener,'LISTEN'),(client,'ESTAB'),(server,'ESTAB'),(udp,'UNCONN'),(peer,'ESTAB')]
            listener=sock(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(Path(tmp)/'listener'));listener.listen(8)
            client=sock(socket.AF_UNIX,socket.SOCK_STREAM);client.bind(str(Path(tmp)/'client'));client.connect(listener.getsockname())
            server=stack.enter_context(listener.accept()[0])
            unixs=[(listener,'LISTEN'),(client,'ESTAB')]
            def inet_check(options,listen=False,udp_only=False):
                r=self.check('netstat '+options,environment())
                assert r.stdout.splitlines()[0] == HEADER+'        PID/Program',r.stdout
                for s,state in sockets:
                    if udp_only and s.type!=socket.SOCK_DGRAM:continue
                    if not udp_only and s.type!=socket.SOCK_STREAM:continue
                    local=s.getsockname();endpoint=f'{local[0]}:{local[1]}'
                    try:
                        peer=s.getpeername();peer=f'{peer[0]}:{peer[1]}'
                    except OSError:peer='0.0.0.0:*' if s.family==2 else ':::*'
                    # Select exact owned endpoint pair and verify one row only.
                    found=[x.split() for x in r.stdout.splitlines()[1:] if len(x.split())>=6 and x.split()[3:5]==[endpoint,peer]]
                    eligible=not listen or state in ('LISTEN','UNCONN')
                    assert len(found)==int(eligible),(options,endpoint,peer,found)
                    if found:
                        fields=found[0]
                        assert fields[0]==('udp' if udp_only else 'tcp')+('6' if s.family==10 else '')
                        assert fields[1]=='0' and fields[2]==('8' if state=='LISTEN' else '0'),fields
                        assert fields[5]==state,fields
                        assert f'pid={os.getpid()},fd={s.fileno()}' in ' '.join(fields),fields
            for opts,l,u in (('-tanp',False,False),('--tcp --listening --programs',True,False),('-uanp',False,True),('--udp --listening --programs',True,True)):
                self.case('owned loopback '+opts,lambda opts=opts,l=l,u=u:inet_check(opts,l,u))
            for opts,listen in (('-xanp',False),('--unix --listening --programs',True)):
                def check(opts=opts,listen=listen):
                    r=self.check('netstat '+opts,environment())
                    for s,state in unixs:
                        lines=[x.split() for x in r.stdout.splitlines()[1:] if s.getsockname() in x.split()]
                        # Accepted endpoint shares the listener path, so ownership
                        # selects this exact socket among the path matches.
                        own=[x for x in lines if f'pid={os.getpid()},fd={s.fileno()}' in ' '.join(x)]
                        assert len(own)==int(not listen or state=='LISTEN'),(opts,own)
                        if own:assert own[0][:6]==['u_str','0','8' if state=='LISTEN' else '0',s.getsockname(),'*',state],own
                self.case('owned private Unix '+opts,check)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--shim',type=Path)
    p.add_argument('--output',type=Path,required=True)
    group=p.add_mutually_exclusive_group()
    group.add_argument('--no-live',action='store_true')
    group.add_argument('--live-only',action='store_true')
    args=p.parse_args()
    if not args.live_only and not args.shim:p.error('--shim is required for deterministic fixture cases')
    suite=Suite(args.binary.resolve(),args.shim.resolve() if args.shim else None)
    with tempfile.TemporaryDirectory(prefix='sol-netstat-',dir='/tmp') as tmp:
        if not args.live_only:
            base=fixtures(Path(tmp)/'fixed')
            suite.fixture_cases(base)
            suite.malformed(tmp)
        if not args.no_live:suite.live(tmp)
    failed=sum(x['status']!='pass' for x in suite.results)
    args.output.write_text(json.dumps(dict(binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),cases=suite.results,failed=failed),indent=2)+'\n')
    print(f'{len(suite.results)-failed}/{len(suite.results)} passed; {failed} failed')
    return bool(failed)

if __name__=='__main__':raise SystemExit(main())
