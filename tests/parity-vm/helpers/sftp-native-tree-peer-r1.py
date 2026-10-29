#!/usr/bin/env python3
"""Disposable-VM-only BASHSSH1 peer serving a fixed private directory tree."""
import json, os, socket, stat, sys, tempfile, time, uuid
from pathlib import Path
case=Path('/tmp/parity-case'); home=Path('/tmp/parity-home'); root=case/'remote'
def record(**x):
    with (home/'native-peer.jsonl').open('a',encoding='utf-8') as f:
        f.write(json.dumps(x,sort_keys=True)+'\n'); f.flush()
def exact(conn,n):
    out=b''
    while len(out)<n:
        part=conn.recv(n-len(out))
        if not part: raise ValueError('short frame')
        out+=part
    return out
try:
    assert os.geteuid()==2000 and os.getuid()==2000 and os.environ.get('HOME')==str(home) and Path.cwd()==case
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    for d in (case,home,root,root/'space dir',root/'other'):
        assert d.is_dir() and not d.is_symlink() and d.stat().st_uid==2000
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM);server.bind(('127.0.0.1',0));server.listen(4);server.settimeout(12)
    port=server.getsockname()[1]
    # Publish a complete ready record in the same directory, atomically.
    fd, ready_tmp = tempfile.mkstemp(prefix='.native-peer-ready-', dir=home)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'pid':os.getpid(),'address':'127.0.0.1','port':port}, stream)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(ready_tmp, home/'native-peer-ready.json')
    finally:
        if os.path.exists(ready_tmp): os.unlink(ready_tmp)
    for index in range(3):
        conn,addr=server.accept();conn.settimeout(4)
        with conn:
            head=b''
            while not head.endswith(b'\n\n'):
                head+=exact(conn,1)
                if len(head)>512:raise ValueError('large header')
            record(event='header',index=index,peer=list(addr),hex=head.hex())
            lines=head[:-2].decode('ascii').split('\n')
            if len(lines)!=3 or lines[0]!='BASHSSH1' or not lines[1].startswith('cmd-len ') or not lines[2].startswith('stdin-len '): raise ValueError('bad header')
            clen=int(lines[1][8:]);ilen=int(lines[2][10:])
            if not (0<=clen<=512 and ilen==0):raise ValueError('invalid lengths')
            raw=exact(conn,clen); record(event='command-bytes',index=index,hex=raw.hex())
            command=raw.decode('utf-8');status=0;err=b''
            if command=='pwd':out=b'/fixture\n'
            elif command=="cd '/fixture' && cd 'space dir' && pwd":
                out=b'/fixture/space dir\n' if (root/'space dir').is_dir() else b''
                if not out:status=1;err=b'fixture missing directory\n'
            elif command=="cd '/fixture/space dir' && ls -la":
                entries=[]
                for item in sorted((root/'space dir').iterdir()):
                    info=item.lstat()
                    if not stat.S_ISREG(info.st_mode):raise ValueError('unexpected tree entry')
                    entries.append(item.name)
                out=('\n'.join(entries)+'\n').encode()
            else:status=127;out=b'';err=b'fixture: unsupported command\n'
            record(event='request',index=index,peer=list(addr),header=head.decode('ascii'),command=command,stdin_len=ilen,rc=status,stdout_hex=out.hex(),stderr_hex=err.hex(),monotonic_ns=time.monotonic_ns())
            conn.sendall(b'BASHSSH1-RESP\nrc %d\nstdout-len %d\nstderr-len %d\n\n'%(status,len(out),len(err))+out+err)
    server.close();record(event='finished',requests=3)
except Exception as exc:
    record(event='peer-error',error=repr(exc));sys.exit(125)
