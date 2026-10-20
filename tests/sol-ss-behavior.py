#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent socket records drive the production ss and shared backend."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('netstat_fixture', ROOT/'tests/sol-netstat-behavior.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
HEADER = 'Netid  State       Recv-Q  Send-Q   Local Address:Port     Peer Address:Port'

def row(proto, recv, send, local, peer, state, owner=''):
    return f'{proto:<6} {state:<11} {recv:<7} {send:<7}  {local:<22} {peer}{owner}\n'

def convert(text):
    lines = text.splitlines()
    out = ''
    for line in lines:
        if line.startswith(f.HEADER):
            out += HEADER + ('  Process' if 'PID/Program' in line else '') + '\n'
        else:
            p = line.split(maxsplit=6)
            out += row(p[0], int(p[1]), int(p[2]), p[3], p[4], p[5], (' '+p[6]) if len(p)>6 else '')
    return out

def expected(proto='tcp', listen=False, large=0):
    return convert(f.expected_inet(proto, listen, large))

def unixmsg(state, path, inode=301, recv=0, send=0):
    original = f.unix(state, path, inode)
    body = original[16:struct.unpack_from('=I',original)[0]]
    return f.msg(body + struct.pack('=HHII',12,4,recv,send))

class Suite(f.Suite):
    def check(self, script, env, output=None, code=0):
        return super().check(script, env, output, code)

    def fixed(self, tmp):
        base = f.fixtures(Path(tmp)/'fixed')
        for transport in ('diag', 'proc'):
            env = f.environment(self.shim, base, transport)
            if transport == 'diag': env['SOL_SS_NO_PROC']='1'
            for options, answer in [
                ('',expected()),('-tna',expected()),('-tnl',expected(listen=True)),
                ('-una',expected('udp')),('-unl',expected('udp',True)),
                ('-xnl',row('u_str',0,0,'/fixture/listener','*','LISTEN')),
                ('-xna',row('u_str',0,0,'/fixture/listener','*','LISTEN')+row('u_str',0,0,'/fixture/connected','*','ESTAB')),
                ('-tuna',expected()+expected('udp')),
                ('-tlan',expected(listen=True)),
            ]:
                self.case(f'{transport} selectors {options}',lambda options=options,answer=answer,env=env:self.check('ss '+options,env,HEADER+'\n'+answer))
            self.case(f'{transport} repeated options reset',lambda env=env:self.check('ss -tnl; ss -una',env,HEADER+'\n'+expected(listen=True)+HEADER+'\n'+expected('udp')))
            self.case(f'{transport} write failure and recovery',lambda env=env:self.check(
                'ss -tnl >/dev/full; a=$?; ss -tnl >/dev/null; b=$?; ss --version >/dev/full; c=$?; ss -tnl >/dev/null; d=$?; printf "%s %s %s %s\\n" "$a" "$b" "$c" "$d"',env,'1 0 1 0\n'))
            self.case(f'{transport} closed output',lambda env=env:self.check('ss -tnl >&-; a=$?; ss -tnl >/dev/null; printf "%s %s\\n" "$a" "$?"',env,'1 0\n'))
            self.case(f'{transport} exact recovery output',lambda env=env:self.check('ss -tnl >/dev/full; a=$?; ss -tna; printf "<status>%s\\n" "$a"',env,HEADER+'\n'+expected()+'<status>1\n'))
            self.case(f'{transport} FD cleanup',lambda env=env:self.fd_cleanup_ss(env))
            # Entry visible to readdir, but readlink is intercepted as ENOENT.
            (base/'proc/4242/fd/10').touch(exist_ok=True)
            def owner(env=env):
                r=self.check('ss -tuxanp',env)
                assert r.stdout.count('pid=4242')==3,r.stdout
                for fd,endpoint in [(7,'127.0.0.1:41001'),(8,'127.0.0.1:43001'),(9,'/fixture/listener')]:
                    line=next(x for x in r.stdout.splitlines() if endpoint in x)
                    assert f'users:(("fixture",pid=4242,fd={fd}))' in line,line
                assert '9999' not in r.stdout and 'fd=10' not in r.stdout
            self.case(f'{transport} ownership denied directory and vanished fd',owner)
        for arg in ('-','operand','-z','--bogus','-tZ','--tcp=bad','--','-4','-6'):
            self.case('invalid '+arg,lambda arg=arg:self.check('ss '+shlex.quote(arg),f.environment(),'',2))
        for arg in ('--help','-h','--version'):
            self.case('information '+arg,lambda arg=arg:self.check('ss '+arg,f.environment()))
        self.case('both transports denied',lambda:self.check('ss -tuxan',f.environment(self.shim,base,'denied'),code=1))
        # Empty files are valid empty snapshots, not inherited rows.
        empty=f.fixtures(Path(tmp)/'empty')
        for p in (empty/'diag').iterdir(): p.write_bytes(f.msg(kind=3))
        for p in (empty/'proc/net').iterdir(): p.write_text('header\n')
        for transport in ('diag','proc'):
            self.case(transport+' empty snapshot',lambda transport=transport:self.check('ss -tuxan',f.environment(self.shim,empty,transport),HEADER+'\n'))

    def fd_cleanup_ss(self, env):
        # Retain the existing persistent-shell FD oracle, selecting ss.
        original=self.binary
        # The inherited checker calls netstat; define it as ss in BASH_ENV.
        with tempfile.NamedTemporaryFile(mode='w',suffix='.sh') as init:
            if env.get('BASH_ENV'): init.write(Path(env['BASH_ENV']).read_text())
            init.write('netstat() { ss -tux "$@"; }\n');init.flush()
            self.fd_cleanup(dict(env,BASH_ENV=init.name))
        self.binary=original

    def errors(self,tmp):
        variants={
            'short inet':f.msg(b'\x02'),
            'unaligned unmatched at buffer end':struct.pack('=IHHII',32767,20,0,0xffffffff,0)+bytes(32751),
            'short error':f.msg(kind=2),
            'oversize length':struct.pack('=IHHII',1000,20,0,0,0)+b'x',
            'partial error':f.inet(2,1,55555,55556)+f.msg(struct.pack('=i',-13)+bytes(16),kind=2),
            'interrupted':f.inet(2,1,55555,55556)+f.msg(kind=3,flags=16),
            'done error':f.msg(struct.pack('=i',-13),kind=3),
            'short done':f.msg(b'x',kind=3),
            'missing done':f.inet(2,1,55555,55556),
            'unknown message':f.msg(kind=99),
        }
        for name,data in variants.items():
            base=f.fixtures(Path(tmp)/name)
            (base/'diag/2-6.bin').write_bytes(data)
            self.case(name+' atomic fallback',lambda base=base:self.check('ss -tna',f.environment(self.shim,base,'diag'),HEADER+'\n'+expected()))
        base=f.fixtures(Path(tmp)/'states')
        states=['ESTAB','SYN-SENT','SYN-RECV','FIN-WAIT-1','FIN-WAIT-2','TIME-WAIT','UNCONN','CLOSE-WAIT','LAST-ACK','LISTEN','CLOSING']
        (base/'diag/2-6.bin').write_bytes(b''.join(f.inet(2,i,44000+i) for i in range(1,12))+f.msg(kind=3))
        (base/'diag/10-6.bin').write_bytes(f.msg(kind=3))
        (base/'proc/net/tcp').write_text('header\n'+''.join(f.proc_row(i,2,i,44000+i) for i in range(1,12)))
        (base/'proc/net/tcp6').write_text('header\n')
        answer=HEADER+'\n'+''.join(row('tcp',3,5,f'127.0.0.1:{44000+i}','0.0.0.0:*',state) for i,state in enumerate(states,1))
        for transport in ('diag','proc'):
            self.case(transport+' all TCP states',lambda transport=transport,base=base,answer=answer:self.check('ss -tna',f.environment(self.shim,base,transport),answer))
        base=f.fixtures(Path(tmp)/'multipart')
        (base/'diag/2-6.bin').write_bytes(f.inet(2,1,55555,55556,seq=0xffffffff)+f.msg(bytes(20),kind=2)+f.inet(2,10,41001))
        (base/'diag/2-6.1.bin').write_bytes(f.inet(2,1,41002,41003,102)+f.msg(kind=3))
        env=f.environment(self.shim,base,'diag');env.update(SOL_SS_NO_PROC='1',SOL_SS_EINTR='1')
        self.case('multipart ACK EINTR and unmatched sequence',lambda:self.check('ss -tna',env,HEADER+'\n'+expected()))
        for flag in ('SOL_SS_TRUNC','SOL_SS_SHORT_SEND','SOL_SS_BIND_FAIL'):
            e=f.environment(self.shim,base,'diag');e[flag]='1'
            self.case(flag+' fallback',lambda e=e:self.check('ss -tna',e,HEADER+'\n'+expected()))
        for name,payload in [
            ('short unix',b'\x01'),
            ('bad unix family',struct.pack('=BBBBIII',2,1,10,0,301,0,0)),
            ('short unix attr',struct.pack('=BBBBIII',1,1,10,0,301,0,0)+struct.pack('=HH',3,0)),
            ('short queue attr',struct.pack('=BBBBIII',1,1,10,0,301,0,0)+struct.pack('=HHI',8,4,2)),
        ]:
            base=f.fixtures(Path(tmp)/name)
            (base/'diag/1-0.bin').write_bytes(f.msg(payload)+f.msg(kind=3))
            self.case(name+' fallback',lambda base=base:self.check('ss -xnl',f.environment(self.shim,base,'diag'),HEADER+'\n'+row('u_str',0,0,'/fixture/listener','*','LISTEN')))
        for table,options in [('tcp','-tna'),('unix','-xna')]:
            base=f.fixtures(Path(tmp)/('read-error-'+table))
            path=base/('proc/net/'+table);path.unlink();path.mkdir()
            self.case(table+' proc read error propagates',lambda base=base,options=options:self.check('ss '+options,f.environment(self.shim,base,'proc'),code=1))
        base=f.fixtures(Path(tmp)/'queues')
        (base/'diag/1-0.bin').write_bytes(unixmsg(1,'\0private',recv=17,send=23)+f.msg(kind=3))
        self.case('Unix abstract name and nonzero queues',lambda:self.check('ss -xan',dict(f.environment(self.shim,base,'diag'),SOL_SS_NO_PROC='1'),HEADER+'\n'+row('u_str',17,23,'@private','*','ESTAB')))
        (base/'proc/net/tcp').write_text('header\nmalformed row\n'+f.proc_row(1,2,1,41002,41003,102)+'0: Z:1 Z:2 01 0:0 0:0 0 1000 0 555\n')
        self.case('proc malformed rows preserve valid queues',lambda:self.check('ss -tna',f.environment(self.shim,base,'proc'),HEADER+'\n'+row('tcp',3,5,'127.0.0.1:41002','127.0.0.1:41003','ESTAB')+row('tcp6',3,5,'::1:42001',':::*','LISTEN')))

    def live(self,tmp):
        with contextlib.ExitStack() as stack:
            def sock(fam,typ):return stack.enter_context(socket.socket(fam,typ))
            sockets=[]
            for family,addr in ((2,'127.0.0.1'),(10,'::1')):
                listener=sock(family,1);listener.bind((addr,0));listener.listen(8)
                client=sock(family,1);client.connect(listener.getsockname())
                server=stack.enter_context(listener.accept()[0]);client.sendall(b'owned queued bytes')
                udp=sock(family,2);udp.bind((addr,0))
                peer=sock(family,2);peer.bind((addr,0));peer.connect(udp.getsockname())
                sockets += [(listener,'LISTEN',0),(client,'ESTAB',0),(server,'ESTAB',18),(udp,'UNCONN',0),(peer,'ESTAB',0)]
            listener=sock(1,1);listener.bind(str(Path(tmp)/'listener'));listener.listen(8)
            client=sock(1,1);client.bind(str(Path(tmp)/'client'));client.connect(listener.getsockname())
            server=stack.enter_context(listener.accept()[0]);server.sendall(b'unix queue')
            unixs=[(listener,'LISTEN',0),(client,'ESTAB',10)]
            external=shutil.which('ss')
            for route in ('diag','proc'):
                env=f.environment(self.shim)
                if route=='diag':env['SOL_SS_NO_PROC']='1'
                if route=='proc':env['SOL_SS_FORCE_PROC']='1'
                for opts in ('-tnap','-tnlp','-unap','-unlp','-xnap','-xnlp'):
                    def check(opts=opts,env=env,route=route):
                        r=self.check('ss '+opts,env)
                        records=[x.split() for x in r.stdout.splitlines()[1:]]
                        candidates=unixs if 'x' in opts else [(s,st,q) for s,st,q in sockets if s.type==(2 if 'u' in opts else 1)]
                        ref=None
                        if external and route=='diag':
                            p=subprocess.run([external,opts],capture_output=True,text=True,check=True)
                            ref=[x.split() for x in p.stdout.splitlines()[1:]]
                        for s,state,queue in candidates:
                            local=s.getsockname()
                            endpoint=local if s.family==1 else f'{local[0]}:{local[1]}'
                            own=f'pid={os.getpid()},fd={s.fileno()}'
                            found=[x for x in records if len(x)>=6 and x[4]==endpoint and own in ' '.join(x)]
                            eligible='l' not in opts or state in ('LISTEN','UNCONN')
                            assert len(found)==int(eligible),(opts,route,endpoint,found)
                            if not found:continue
                            x=found[0];assert x[1]==state,(x,state)
                            assert int(x[2])==(0 if route=='proc' and s.family==1 else queue),x
                            if state=='LISTEN': assert int(x[3])==(8 if route=='diag' else 0),x
                            if s.family!=1:
                                try:p=s.getpeername();peer=f'{p[0]}:{p[1]}'
                                except OSError:peer='0.0.0.0:*' if s.family==2 else ':::*'
                                assert x[5]==peer,(x,peer)
                            if ref is not None:
                                matching=[v for v in ref if own in ' '.join(v)]
                                assert len(matching)==1,(own,matching)
                                # Single-family ss omits Netid for inet; Unix retains it.
                                y=matching[0];offset=1 if y[0].startswith('u_') else 0
                                assert y[offset:offset+3]==x[1:4],(x,y)
                                assert y[offset+3].replace('[','').replace(']','')==endpoint,(x,y)
                    self.case(f'owned {route} {opts}'+(' external selected records' if external and route=='diag' else ''),check)
            self.reference=external


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--shim',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--no-live',action='store_true')
    a=p.parse_args();suite=Suite(a.binary.resolve(),a.shim.resolve())
    with tempfile.TemporaryDirectory(prefix='sol-ss-') as tmp:
        suite.fixed(tmp);suite.errors(tmp)
        if not a.no_live:suite.live(tmp)
    failed=sum(c['status']!='pass' for c in suite.results)
    a.output.write_text(json.dumps(dict(cases=suite.results,failed=failed,external_ss=getattr(suite,'reference',None),binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest()),indent=2)+'\n')
    print(f'{len(suite.results)-failed}/{len(suite.results)} passed; {failed} failed')
    return bool(failed)

if __name__=='__main__':raise SystemExit(main())
