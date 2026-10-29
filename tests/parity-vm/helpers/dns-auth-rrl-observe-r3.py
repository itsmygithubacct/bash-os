#!/usr/bin/env python3
"""VM-only UDP observer; durable packet outcomes precede cleanup/review."""
import json, os, select, socket, struct, sys, time, uuid
from pathlib import Path
def guard():
    marker=Path('/etc/bashos-parity-vm').read_text().strip(); uuid.UUID(marker)
    if (Path('/run/bashos-parity-vm-identity').read_text().strip().lower()!=marker.lower() or
        Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=Path('/tmp/parity-case') or
        os.environ.get('HOME')!='/tmp/parity-home'):
        raise RuntimeError('not the unprivileged disposable guest')
guard()
home=Path('/tmp/parity-home'); mode=sys.argv[1]; port=int(sys.argv[2]); pid=int(sys.argv[3])
if (mode,port) not in (('control',21751),('limited',21752)) or pid<=1:
    raise RuntimeError('unexpected mode, loopback port or pid')
def proc_identity():
    raw=Path('/proc/%d/stat'%pid).read_text(); parts=raw[raw.rfind(')')+2:].split()
    return {'state':parts[0], 'ppid':int(parts[1]), 'starttime':int(parts[19])}
initial=proc_identity()
if initial['ppid']!=os.getppid() or initial['state'] in ('Z','X'):
    raise RuntimeError('server is not a live child of the fixture shell')
events=home/('rrl-'+mode+'-events.jsonl'); reached=home/('rrl-'+mode+'-reached-failures.jsonl')
question=b'\x03www\x07example\x04test\x00\x00\x01\x00\x01'
def log(path, obj):
    with path.open('a',encoding='utf-8') as f:
        f.write(json.dumps(obj,sort_keys=True)+'\n'); f.flush()
        if path==reached: os.fsync(f.fileno())
def owned():
    fds=[]
    for f in Path('/proc/%d/fd'%pid).iterdir():
        try: fds.append(os.readlink(f))
        except OSError: pass
    found={}
    for proto,state in [('tcp','0A'),('udp','07')]:
        for row in Path('/proc/net/'+proto).read_text().splitlines()[1:]:
            x=row.split()
            if x[1]=='0100007F:%04X'%port and x[3]==state and 'socket:['+x[9]+']' in fds:
                found[proto]={'inode':x[9],'address':x[1]}
    return found
def dead():
    try:
        info=proc_identity(); return info['state'] in ('Z','X') or info['starttime']!=initial['starttime'] or info['ppid']!=initial['ppid']
    except FileNotFoundError: return True
try:
    deadline=time.monotonic()+8
    found={}
    while time.monotonic()<deadline:
        if dead(): break
        found=owned()
        if set(found)=={'tcp','udp'}: break
        time.sleep(.02)
    exe=os.readlink('/proc/%d/exe'%pid) if not dead() else None
    same=exe is not None and os.path.samefile('/proc/%d/exe'%pid,'/opt/bashos-parity/candidate')
    log(events,{'event':'identity','server_pid':pid,'starttime':initial['starttime'],'parent_pid':initial['ppid'],'exe':exe,'candidate_exe_matches':same,'listeners':found,'time_ns':time.monotonic_ns()})
    if set(found)!={'tcp','udp'} or not same:
        log(events,{'event':'incomplete','reason':'owned candidate listeners unavailable'});sys.exit(125)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.connect(('127.0.0.1',port))
    log(events,{'event':'socket','local':s.getsockname(),'peer':s.getpeername()})
    sent={};seen=set();first=None
    for i in range(20):
        ident=0x6100+i; packet=struct.pack('!6H',ident,0x0100,1,0,0,0)+question
        before=time.monotonic_ns(); n=s.send(packet); after=time.monotonic_ns(); first=before if first is None else first
        sent[ident]=packet;log(events,{'event':'send','id':ident,'hex':packet.hex(),'before_ns':before,'after_ns':after,'bytes':n})
    deadline=time.monotonic()+2; exit_ns=None
    while time.monotonic()<deadline:
        if exit_ns is None and dead(): exit_ns=time.monotonic_ns();log(events,{'event':'server-exit-observed','time_ns':exit_ns})
        ready,_,_=select.select([s],[],[],min(.01,max(0,deadline-time.monotonic())))
        if not ready:continue
        try: packet=s.recv(65535)
        except ConnectionRefusedError:
            log(events,{'event':'icmp-unreachable','time_ns':time.monotonic_ns()});continue
        now=time.monotonic_ns(); obs={'event':'receive','hex':packet.hex(),'time_ns':now}; failures=[]
        if len(packet)<12: failures.append('short DNS datagram')
        else:
            ident,flags,qd,an,ns,ar=struct.unpack('!6H',packet[:12]);obs.update(id=ident,flags=flags,qd=qd,an=an,ns=ns,ar=ar)
            if ident not in sent: failures.append('unknown transaction id')
            elif ident in seen: failures.append('duplicate transaction id')
            else:
                seen.add(ident);q=sent[ident]
                if not flags&0x8000 or not flags&0x0400 or flags&0x780f or qd!=1 or packet[12:len(q)]!=q[12:]: failures.append('invalid DNS response header or question')
                if flags&0x0200 and (an or ns or ar or len(packet)!=len(q)):failures.append('malformed truncated response')
                if not flags&0x0200:
                    off=len(q); owner=q[12:-4]
                    if packet[off:off+2]==b'\xc0\x0c': off+=2
                    elif packet[off:off+len(owner)]==owner: off+=len(owner)
                    else: off=len(packet)
                    if len(packet)<off+14 or an!=1 or packet[off:off+4]!=b'\x00\x01\x00\x01' or packet[off+8:off+10]!=b'\x00\x04' or packet[off+10:off+14]!=bytes([192,0,2,10]): failures.append('invalid full A answer')
        for reason in failures:log(reached,{'event':'candidate-packet-failure','mode':mode,'reason':reason,'packet':obs,'server_pid':pid})
        log(events,obs)
    s.close();log(events,{'event':'observer-complete','first_send_ns':first,'last_send_ns':after,'server_exit_observed_ns':exit_ns,'unique_responses':len(seen)})
except SystemExit: raise
except Exception as exc:
    log(events,{'event':'incomplete','reason':repr(exc),'time_ns':time.monotonic_ns()});sys.exit(125)
