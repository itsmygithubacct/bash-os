#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-child sock_diag fault injection with a separate protocol control."""
import base64
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')
ALLOW=0x7fff0000;NOTIFY=0x7fc00000;RECV=0xc0502100;SEND=0xc0182101;CONTINUE=1
FAKE=40001;UNMATCHED=40002;RETRIED=40003


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.getuid()!=2000 or os.geteuid()!=2000 or
        Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME)):
        raise RuntimeError('disposable guest identity mismatch')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    links=json.loads(subprocess.run(['/usr/sbin/ip','-j','link','show'],capture_output=True,text=True,timeout=3,check=True).stdout)
    if virt not in ('qemu','kvm') or [x['ifname'] for x in links]!=['lo']:
        raise RuntimeError('expected loopback-only disposable guest')


def save(name,data): (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def encode_nl(kind,flags,seq,payload):
    return struct.pack('=IHHII',16+len(payload),kind,flags,seq,0)+payload


def diag(seq,port):
    ident=(struct.pack('!HH',port,0)+socket.inet_pton(socket.AF_INET,'127.0.0.1')+bytes(12)+bytes(16)+struct.pack('=III',0,0xffffffff,0xffffffff))
    payload=struct.pack('=BBBB',socket.AF_INET,10,0,0)+ident+struct.pack('=IIIII',0,2,5,2000,60001)
    if len(payload)!=72:raise RuntimeError('unexpected inet_diag message size')
    return encode_nl(20,2,seq,payload)


def done(seq,flags=2):return encode_nl(3,flags,seq,struct.pack('=i',0))


def plan(mode,seq,request):
    if mode=='retry':
        ack=encode_nl(2,2,seq,struct.pack('=i',0)+request[:16])
        return [('errno',errno.EINTR),('data',diag((seq+1)&0xffffffff,UNMATCHED)),('data',ack),('data',diag(seq,FAKE)),('data',done(seq))]
    if mode=='malformed':return [('data',diag(seq,FAKE)),('data',struct.pack('=IHH',8,20,2))]
    if mode=='interrupt':return [('data',diag(seq,FAKE)),('data',done(seq,2|0x10))]
    if mode=='error':return [('data',diag(seq,FAKE)),('data',encode_nl(2,2,seq,struct.pack('=i',-errno.EINVAL)+request[:16]))]
    raise ValueError('unknown injection mode')


def memory(pid,address,length,write=None):
    if length<0 or length>4096:raise RuntimeError('memory operation outside bound')
    fd=os.open('/proc/%d/mem'%pid,os.O_RDWR if write is not None else os.O_RDONLY)
    try:
        if write is None:return os.pread(fd,length,address)
        if len(write)!=length or os.pwrite(fd,write,address)!=length:raise RuntimeError('short tracee memory write')
        result=os.pread(fd,length,address)
        if result!=write:raise RuntimeError('tracee memory write verification failed')
        return result
    finally:os.close(fd)


def install():
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.restype=ctypes.c_void_p;lib.seccomp_init.argtypes=[ctypes.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p]
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_notify_fd.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(ALLOW)
    if not ctx:raise RuntimeError('seccomp_init failed')
    for name in (b'sendto',b'recvfrom'):
        nr=lib.seccomp_syscall_resolve_name(name)
        if nr<0 or lib.seccomp_rule_add_array(ctx,NOTIFY,nr,0,None)!=0:raise RuntimeError('seccomp rule failed')
    if lib.seccomp_load(ctx)!=0:raise RuntimeError('seccomp_load failed')
    fd=lib.seccomp_notify_fd(ctx)
    if fd<0:raise RuntimeError('no notification fd')
    os.set_inheritable(fd,False)
    return fd


def control_probe(mode):
    if os.uname().machine!='x86_64':raise RuntimeError('amd64 syscall table required')
    seq=0x129ac1
    req=struct.pack('=IHHII',72,20,0x301,seq,0)+struct.pack('=BBBBI',socket.AF_INET,socket.IPPROTO_TCP,0,0,0xfff)+bytes(48)
    records=[]
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
        s.bind((0,0))
        if s.sendto(req,(0,0))!=len(req):raise RuntimeError('probe request was short')
        lib=ctypes.CDLL(None,use_errno=True)
        count=5 if mode=='retry' else 2
        for _ in range(count):
            buf=ctypes.create_string_buffer(32768);ctypes.set_errno(0)
            n=lib.syscall(45,s.fileno(),ctypes.byref(buf),32768,0,0,0)
            records.append({'result':int(n),'errno':ctypes.get_errno() if n<0 else 0,
                            'hex':buf.raw[:n].hex() if n>=0 else ''})
    decoded=[]
    for actual in records:
        if actual['result']<0:
            decoded.append({'errno':actual['errno']});continue
        data=bytes.fromhex(actual['hex'])
        if len(data)<16:
            decoded.append({'short_message_hex':data.hex()});continue
        length,kind,flags,nseq,pid=struct.unpack_from('=IHHII',data)
        item={'length':length,'kind':kind,'flags':flags,'sequence':nseq}
        if length!=len(data):raise RuntimeError('probe netlink frame length mismatch')
        payload=data[16:]
        if kind==20:
            if len(payload)<72:raise RuntimeError('probe diagnostic message too short')
            item.update(family=payload[0],state=payload[1],port=struct.unpack_from('!H',payload,4)[0],
                        source=socket.inet_ntop(socket.AF_INET,payload[8:12]),
                        rqueue=struct.unpack_from('=I',payload,56)[0],wqueue=struct.unpack_from('=I',payload,60)[0])
        elif kind in (2,3):item['error']=struct.unpack_from('=i',payload)[0]
        decoded.append(item)
    def valid(item, expected_seq, expected_port):
        return (item.get('kind')==20 and item.get('sequence')==expected_seq and item.get('family')==socket.AF_INET and
                item.get('state')==10 and item.get('port')==expected_port and item.get('source')=='127.0.0.1' and
                item.get('rqueue')==2 and item.get('wqueue')==5)
    if mode=='retry':
        good=(decoded[0].get('errno')==errno.EINTR and valid(decoded[1],seq+1,UNMATCHED) and
              decoded[2].get('kind')==2 and decoded[2].get('error')==0 and decoded[2].get('sequence')==seq and
              valid(decoded[3],seq,FAKE) and decoded[4].get('kind')==3 and decoded[4].get('error')==0)
    elif mode=='malformed':good=valid(decoded[0],seq,FAKE) and len(bytes.fromhex(decoded[1].get('short_message_hex','')))==8
    elif mode=='interrupt':good=valid(decoded[0],seq,FAKE) and decoded[1].get('kind')==3 and bool(decoded[1].get('flags',0)&0x10)
    else:good=valid(decoded[0],seq,FAKE) and decoded[1].get('kind')==2 and decoded[1].get('error')==-errno.EINVAL
    save('probe-'+mode+'.json',{'request_hex':req.hex(),'records':records,'independent_decoding':decoded})
    if not good:raise RuntimeError('independent protocol decoding mismatch')
    print('control=ok')


def validate_candidate(mode,kind,status,stdout,stderr,port,events):
    lines=stdout.decode('utf-8','replace').splitlines();errors=[];rows=[]
    expected_header='Netid' if kind=='ss' else 'Proto'
    if not lines or not lines[0].startswith(expected_header):errors.append('missing table header')
    for line in lines[1:]:
        fields=line.split()
        if len(fields)<6:errors.append('short row');continue
        if kind=='ss':
            family,state,recv,send,local,peer=fields[:6]
        else:
            family,recv,send,local,peer,state=fields[:6]
        rows.append({'raw':line,'family':family,'state':state,'recv':recv,'send':send,'local':local,'peer':peer})
    fake=[r for r in rows if r['local'].endswith(':'+str(FAKE))]
    unmatched=[r for r in rows if r['local'].endswith(':'+str(UNMATCHED))]
    actual=[r for r in rows if r['local'].endswith(':'+str(port))]
    retried=[r for r in rows if r['local'].endswith(':'+str(RETRIED))]
    receives=[e for e in events if e.get('operation')=='recvfrom' and e.get('family')==socket.AF_INET and e.get('response_status')=='sent']
    if len(receives)<(5 if mode=='retry' else 2):errors.append('injected branch was not reached')
    if mode=='retry':
        if (status!=0 or len(fake)!=1 or unmatched or (fake and (fake[0]['family'],fake[0]['state'],fake[0]['recv'],fake[0]['send'],fake[0]['local'],fake[0]['peer']) != ('tcp','LISTEN','2','5','127.0.0.1:40001','0.0.0.0:*'))):
            errors.append('EINTR/ACK/unmatched sequence handling or diagnostic fields')
    else:
        if fake or unmatched:errors.append('partial netlink rows escaped')
        failure_reported=status!=0 and bool(stderr.strip()) and len(actual)<=1
        fallback=status==0 and len(actual)==1
        if mode=='interrupt':
            requests=[e for e in events if e.get('operation')=='sendto' and e.get('family')==socket.AF_INET]
            retried_ok=len(requests)>=2 and status==0 and len(retried)==1
            if not (retried_ok or failure_reported or (kind=='netstat' and fallback)):
                errors.append('interrupted dump neither retried nor reported')
        elif not (fallback or failure_reported):errors.append('fallback/error handling')
    return {'errors':errors,'rows':rows,'fake_count':len(fake),'unmatched_count':len(unmatched),'actual_count':len(actual)}


def run(mode,kind,binary=None):
    if mode not in ('retry','malformed','interrupt','error') or kind not in ('control','ss','netstat'):
        raise ValueError('unknown scenario')
    report={'mode':mode,'kind':kind,'events':[],'request_count':0,
            'netns':os.readlink('/proc/self/ns/net'),'uid_map':Path('/proc/self/uid_map').read_text()}
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0));listener.listen(3)
    port=listener.getsockname()[1]
    if port in (FAKE,UNMATCHED,RETRIED):raise RuntimeError('fixture port collided with injected port')
    report['fixture_socket']={'port':port,'fd':listener.fileno(),'inode':os.fstat(listener.fileno()).st_ino}
    report['proc_tcp_before']=Path('/proc/net/tcp').read_text();report['proc_tcp6_before']=Path('/proc/net/tcp6').read_text()
    if len(report['proc_tcp_before'])>512*1024 or len(report['proc_tcp6_before'])>512*1024:raise RuntimeError('proc table exceeds evidence bound')
    proc_matches=[]
    for line in report['proc_tcp_before'].splitlines()[1:]:
        fields=line.split()
        if len(fields)>9 and int(fields[9])==report['fixture_socket']['inode']:
            proc_matches.append(fields)
    if len(proc_matches)!=1 or int(proc_matches[0][1].split(':')[1],16)!=port or int(proc_matches[0][3],16)!=10:
        raise RuntimeError('owned listener proc control failed')
    report['fixture_proc_row']=proc_matches[0]
    parent,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    outpath=HOME/('fault-'+kind+'-'+mode+'.out');errpath=HOME/('fault-'+kind+'-'+mode+'.err')
    outf=os.open(outpath,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600);errf=os.open(errpath,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    pid=os.fork()
    if pid==0:
        try:
            parent.close();os.dup2(outf,1);os.dup2(errf,2);os.close(outf);os.close(errf)
            fd=install();socket.send_fds(peer,[b'L'],[fd])
            if kind=='control':argv=['/usr/bin/python3',__file__,'probe',mode]
            else:
                script=r'''[[ $UID == 2000 && $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
'''+f'[[ $(type -t {kind}) == builtin ]] || exit 99\n{kind} -tn\n'
                argv=[binary,'--noprofile','--norc','-c',script]
            os.execv(argv[0],argv)
        except BaseException as exc:
            os.write(2,('fault child setup: '+str(exc)+'\n').encode())
        os._exit(126)
    peer.close();os.close(outf);os.close(errf)
    report['child_pid']=pid;status=None;tracked={};notif=None
    try:
        ready,_,_=select.select([parent],[],[],8)
        if not ready:raise RuntimeError('notification listener handshake timeout')
        _,fds,_,_=socket.recv_fds(parent,16,1)
        if len(fds)!=1:raise RuntimeError('missing notification listener')
        notif=fds[0]
        while status is None:
            donepid,wait=os.waitpid(pid,os.WNOHANG)
            if donepid:status=os.waitstatus_to_exitcode(wait);break
            ready,_,_=select.select([notif],[],[],0.05)
            if not ready:continue
            request=bytearray(80)
            try:fcntl.ioctl(notif,RECV,request,True)
            except OSError as exc:
                if exc.errno in (errno.ENOENT,errno.EINTR):continue
                raise
            ident,who,nflags,nr,arch,ip=struct.unpack_from('<QIIiIQ',request);args=struct.unpack_from('<6Q',request,32)
            response=struct.pack('<QqiI',ident,0,0,CONTINUE)
            event={'request_hex':request.hex(),'id':ident,'pid':who,'nr':nr,'arch':arch,'args':list(args),'reply':'continue'}
            # x86_64 syscall numbers; only the remembered direct child may be modified.
            if who==pid and nr==44:
                fdnum,length=args[0],args[2]
                if 16<=length<=256:
                    packet=memory(pid,args[1],length)
                    length_field,typ,nlflags,seq,nlpid=struct.unpack_from('=IHHII',packet)
                    if typ==20 and length_field==length and len(packet)>=17:
                        family=packet[16]
                        prior=sum(1 for event in report['events'] if event.get('operation')=='sendto' and event.get('family')==socket.AF_INET)
                        if family==socket.AF_INET and mode=='interrupt' and prior:
                            queue=[('data',diag(seq,RETRIED)),('data',done(seq))]
                        else:
                            queue=plan(mode,seq,packet) if family==socket.AF_INET else [('data',done(seq))]
                        tracked[fdnum]={'seq':seq,'family':family,'queue':queue}
                        response=struct.pack('<QqiI',ident,length,0,0)
                        event.update(operation='sendto',family=family,sequence=seq,packet_hex=packet.hex(),reply='value:'+str(length))
                        report['request_count']+=1
            elif who==pid and nr==45 and args[0] in tracked:
                item=tracked[args[0]]
                if not item['queue']:raise RuntimeError('candidate requested beyond injected dump')
                action,value=item['queue'].pop(0)
                if action=='errno':
                    response=struct.pack('<QqiI',ident,0,-value,0);reply='errno:'+str(value);payload=''
                else:
                    if len(value)>args[2]:raise RuntimeError('tracee receive buffer too small')
                    memory(pid,args[1],len(value),value)
                    response=struct.pack('<QqiI',ident,len(value),0,0);reply='value:'+str(len(value));payload=value.hex()
                event.update(operation='recvfrom',family=item['family'],sequence=item['seq'],payload_hex=payload,reply=reply)
            event['response_hex']=response.hex()
            try:fcntl.ioctl(notif,SEND,response);event['response_status']='sent'
            except OSError as exc:
                event['response_status']='send-errno:'+str(exc.errno)
                if exc.errno!=errno.ENOENT:raise
            report['events'].append(event)
            if len(report['events'])>256:raise RuntimeError('notification event bound exceeded')
        if outpath.stat().st_size>512*1024 or errpath.stat().st_size>256*1024:raise RuntimeError('command output exceeds evidence bound')
        report['status']=status;report['stdout_base64']=base64.b64encode(outpath.read_bytes()).decode();report['stderr_base64']=base64.b64encode(errpath.read_bytes()).decode()
        report['proc_tcp_after']=Path('/proc/net/tcp').read_text();report['proc_tcp6_after']=Path('/proc/net/tcp6').read_text()
        if report['request_count']==0:raise RuntimeError('no recognized diagnostic request')
        if kind=='control':
            if status!=0 or outpath.read_text()!='control=ok\n':raise RuntimeError('independent protocol control failed')
        else:
            report['comparison']=validate_candidate(mode,kind,status,outpath.read_bytes(),errpath.read_bytes(),port,report['events'])
            if report['comparison']['errors']:raise RuntimeError('candidate protocol assertions failed')
            print(kind+'-'+mode+'=verified')
    except Exception as exc:
        report['fatal_error']=str(exc);raise
    finally:
        if notif is not None:os.close(notif)
        parent.close();listener.close();save('fault-'+kind+'-'+mode+'.json',report)


def main():
    guard()
    if sys.argv[1]=='probe':control_probe(sys.argv[2])
    elif sys.argv[1]=='run':run(sys.argv[2],sys.argv[3],sys.argv[4] if len(sys.argv)>4 else None)
    else:raise ValueError('unknown mode')


if __name__=='__main__':main()
