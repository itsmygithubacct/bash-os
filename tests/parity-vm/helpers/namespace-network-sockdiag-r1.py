#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-socket tests and independent UNIX sock_diag decoder for a guest VM."""
import base64
import collections
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case'); HOME=Path('/tmp/parity-home')
OBSERVER='/opt/bashos-parity/harness/helpers/namespace-network-observe-r1.py'


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME)):
        raise RuntimeError('disposable guest identity mismatch')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    links=json.loads(subprocess.run(['/usr/sbin/ip','-j','link','show'],capture_output=True,text=True,timeout=3,check=True).stdout)
    if virt not in ('qemu','kvm') or [v['ifname'] for v in links]!=['lo']:
        raise RuntimeError('expected loopback-only disposable guest')


def save(name,data):
    (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def run_process(args):
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err=proc.communicate(timeout=20)
    if len(out)>512*1024 or len(err)>256*1024: raise RuntimeError('captured command output exceeds bound')
    return {'argv':args,'pid':proc.pid,'status':proc.returncode,
            'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode()}


def bytes_out(record): return base64.b64decode(record['stdout_base64'])


def raw_proc():
    result={}
    for name in ('tcp','tcp6','udp','udp6','unix'):
        path=Path('/proc/net')/name
        if path.exists():
            text=path.read_text()
            if len(text)>512*1024: raise RuntimeError('proc table exceeds bound')
            result[name]=text
    return result


def diag_unix():
    seq=0x42a611
    req=struct.pack('=BBHIIIII',socket.AF_UNIX,0,0,0xffffffff,0,0x15,0xffffffff,0xffffffff)
    message=struct.pack('=IHHII',16+len(req),20,0x301,seq,0)+req
    report={'socket_request':{'family':socket.AF_NETLINK,'type':socket.SOCK_RAW,'protocol':4},
            'send_request_hex':message.hex(),'datagrams':[],'records':[]}
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
        s.bind((0,0)); report['socket_local']=s.getsockname()
        sent=s.sendto(message,(0,0));report['send_reply']=sent
        if sent!=len(message): raise RuntimeError('short netlink request')
        s.settimeout(5); done=False
        while not done:
            data,anc,flags,addr=s.recvmsg(32768)
            report['datagrams'].append({'hex':data.hex(),'flags':flags,'sender':addr})
            if flags & socket.MSG_TRUNC or sum(len(x['hex'])//2 for x in report['datagrams'])>512*1024:
                raise RuntimeError('truncated or oversized diagnostic dump')
            pos=0
            while pos<len(data):
                if pos+16>len(data): raise RuntimeError('short netlink header')
                length,typ,nflags,nseq,pid=struct.unpack_from('=IHHII',data,pos)
                if length<16 or pos+length>len(data) or nseq!=seq or nflags & 0x10:
                    raise RuntimeError('invalid netlink message framing')
                payload=data[pos+16:pos+length]
                if typ==3:
                    if payload and (len(payload)<4 or struct.unpack_from('=i',payload)[0]!=0):
                        raise RuntimeError('netlink dump completion error')
                    done=True
                elif typ==2:
                    if len(payload)<4 or struct.unpack_from('=i',payload)[0]!=0:
                        raise RuntimeError('netlink error')
                elif typ==20:
                    if len(payload)<16: raise RuntimeError('short unix_diag message')
                    family,stype,state,pad,inode,c0,c1=struct.unpack_from('=BBBBIII',payload)
                    if family!=socket.AF_UNIX: raise RuntimeError('unexpected diagnostic family')
                    rec={'family':family,'type':stype,'state':state,'inode':inode,'cookie':[c0,c1],
                         'nl_flags':nflags,'nl_sequence':nseq,'nl_pid':pid,'attributes':[]}
                    off=16
                    while off<len(payload):
                        if off+4>len(payload): raise RuntimeError('short diagnostic attribute')
                        alen,atype=struct.unpack_from('=HH',payload,off)
                        if alen<4 or off+alen>len(payload): raise RuntimeError('bad diagnostic attribute')
                        value=payload[off+4:off+alen]; rec['attributes'].append({'type':atype,'hex':value.hex()})
                        if atype==0:
                            value=value.rstrip(b'\x00')
                            rec['name']=('@'+value[1:].decode('utf-8','replace')) if value.startswith(b'\x00') else value.decode('utf-8','replace')
                        elif atype==4:
                            if len(value)<8: raise RuntimeError('short rqlen attribute')
                            rec['rqueue'],rec['wqueue']=struct.unpack_from('=II',value)
                        off+=(alen+3)&~3
                    if off!=len(payload): raise RuntimeError('misaligned diagnostic attributes')
                    report['records'].append(rec)
                else: raise RuntimeError('unexpected netlink message type')
                pos+=(length+3)&~3
            if pos!=len(data): raise RuntimeError('misaligned netlink datagram')
    return report


def verify_events(rows):
    for row in rows:
        request=bytes.fromhex(row['request_hex']); response=bytes.fromhex(row['response_hex'])
        if len(request)!=80 or len(response)!=24 or row.get('response_status')!='sent':
            raise RuntimeError('invalid or unsent notification event')
        ident,pid,flags,nr,arch,ip=struct.unpack_from('<QIIiIQ',request)
        args=list(struct.unpack_from('<6Q',request,32))
        rid,value,error,rflags=struct.unpack('<QqiI',response)
        if (ident,pid,nr,arch,ip,args,ident)!=(row['id'],row['pid'],row['syscall_number'],row['arch'],row['instruction_pointer'],row['args'],rid):
            raise RuntimeError('raw/decoded notification mismatch')
        if row['reply']=='errno:1' and (error!=-1 or rflags!=0):
            raise RuntimeError('invalid EPERM response')


def shell(binary,command):
    # The separately executed shell repeats its guard before calling a builtin.
    g=r'''[[ $UID == 2000 && $EUID == 2000 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
'''
    return [binary,'--noprofile','--norc','-c',g+command]


def parse_candidate(raw,kind):
    lines=raw.decode('utf-8','replace').splitlines()
    expected='Proto' if kind=='netstat' else 'Netid'
    if not lines or not lines[0].startswith(expected): raise ValueError('missing output heading')
    rows=[]
    for line in lines[1:]:
        fields=line.split()
        if len(fields)<6: raise ValueError('short candidate row: '+line)
        if kind=='netstat':
            rows.append({'type':fields[0],'rqueue':fields[1],'wqueue':fields[2],
                         'local':fields[3],'peer':fields[4],'state':fields[5]})
        else:
            rows.append({'type':fields[0],'state':fields[1],'rqueue':fields[2],
                         'wqueue':fields[3],'local':fields[4],'peer':fields[5]})
    return rows


def unix_rows(text):
    result={}
    for line in text.splitlines()[1:]:
        parts=line.split(None,7)
        if len(parts)<7: continue
        result[int(parts[6])]={'raw':line,'flags':int(parts[3],16),'type':int(parts[4],16),
                               'state':int(parts[5],16),'path':parts[7] if len(parts)>7 else ''}
    return result


def inet_row(text,inode):
    for line in text.splitlines()[1:]:
        parts=line.split()
        if len(parts)>9 and int(parts[9])==inode:
            tx,rx=parts[4].split(':')
            return {'raw':line,'state':int(parts[3],16),'tx':int(tx,16),'rx':int(rx,16)}
    raise RuntimeError('fixture inet socket absent from proc')


def simple_sockets(label):
    root=CASE/('socket-'+label);root.mkdir()
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); listener.bind(str(root/'server')); listener.listen(4)
    client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); client.bind(str(root/'client')); client.connect(str(root/'server'))
    accepted,_=listener.accept(); client.sendall(b'queued-fixture-bytes')
    tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.bind(('127.0.0.1',0));tcp.listen(3)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
    sockets={'listener':listener,'client':client,'accepted':accepted,'tcp':tcp,'udp':udp}
    info={k:{'fd':s.fileno(),'inode':os.fstat(s.fileno()).st_ino,'name':s.getsockname()} for k,s in sockets.items()}
    info['listener']['acceptconn']=listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)
    info['client']['peer']=client.getpeername(); info['accepted']['peer']=accepted.getpeername()
    return sockets,info


def verify_controls(info,proc,diag,native):
    if native['status']!=0: raise RuntimeError('native ss failed')
    rows=unix_rows(proc['unix']); byino={r['inode']:r for r in diag['records']}
    for label in ('listener','client','accepted'):
        inode=info[label]['inode']
        if inode not in rows or inode not in byino: raise RuntimeError('owned unix socket absent from proc/diag')
        if rows[inode]['type']!=socket.SOCK_STREAM: raise RuntimeError('proc type not stream')
    if info['listener']['acceptconn']!=1 or not rows[info['listener']['inode']]['flags'] & 0x10000:
        raise RuntimeError('listener control failed')
    if rows[info['client']['inode']]['state']!=3 or rows[info['accepted']['inode']]['state']!=3:
        raise RuntimeError('connected SS state not observed')
    if byino[info['listener']['inode']]['state']!=10 or any(byino[info[k]['inode']]['state']!=1 for k in ('client','accepted')):
        raise RuntimeError('unix diagnostic states differ')
    if byino[info['accepted']['inode']].get('rqueue',0)<=0:
        raise RuntimeError('queued payload did not produce a diagnostic receive queue')
    for k in ('listener','client','accepted'):
        rec=byino[info[k]['inode']]
        if 'rqueue' not in rec or 'wqueue' not in rec: raise RuntimeError('missing queue attributes')
    inet_row(proc['tcp'],info['tcp']['inode']);inet_row(proc['udp'],info['udp']['inode'])
    return byino


def simple(mode,binary=None):
    sockets,info=simple_sockets(mode)
    report={'mode':mode,'socket_identities':info,'process_id':os.getpid(),
            'namespaces':{n:os.readlink('/proc/self/ns/'+n) for n in ('net','user','pid','mnt')}}
    try:
        proc=raw_proc();diag=diag_unix();native=run_process(['/usr/bin/ss','-axn'])
        report.update(proc=proc,netlink=diag,native=native)
        byino=verify_controls(info,proc,diag,native)
        if mode=='control': save('socket-control.json',report);return
        if mode=='unix':
            cmd=shell(binary,'[[ $(type -t netstat) == builtin ]] || exit 99\nnetstat -axn\n')
            candidate=run_process(cmd);report['candidate']=candidate
            try: rows=parse_candidate(bytes_out(candidate),'netstat'); error=None
            except ValueError as exc: rows=[]; error=str(exc)
            failures=[]
            if candidate['status']!=0 or error: failures.append('candidate status or output format')
            for label,want_state in [('listener','LISTENING'),('accepted','CONNECTED'),('client','CONNECTED')]:
                rec=byino[info[label]['inode']]; name=rec.get('name','*') or '*'
                selected=[x for x in rows if x['local']==name and x['state']==want_state and
                          x['type'] in ('u_str','STREAM') and x['rqueue']==str(rec['rqueue']) and x['wqueue']==str(rec['wqueue'])]
                if len(selected)!=1: failures.append(label+' expected state, type, path and queue row missing')
            report.update(candidate_rows=rows,parse_error=error,failures=failures)
        elif mode=='fallback':
            cmd=[sys.executable,OBSERVER,'--notify','socket:0=16,2=4','--reply','socket=EPERM',
                 '--log-args','socket=0,1,2','--log',str(HOME/'fallback-events.jsonl'),'--']+shell(binary,
                 '[[ $(type -t ss) == builtin ]] || exit 99\nss -atuxn\n')
            candidate=run_process(cmd);report['candidate']=candidate
            try: rows=parse_candidate(bytes_out(candidate),'ss');error=None
            except ValueError as exc: rows=[];error=str(exc)
            log=[json.loads(line) for line in (HOME/'fallback-events.jsonl').read_text().splitlines() if line]
            verify_events(log)
            requests=[r for r in log if r.get('syscall')=='socket' and r['args'][0]==socket.AF_NETLINK and r['args'][2]==4 and r['reply']=='errno:1' and r.get('response_status')=='sent']
            failures=[]
            if candidate['status']!=0 or error or len(requests)<5: failures.append('candidate status, format or sock_diag denials')
            for label,table,want_type,want_state in [('tcp','tcp','tcp','LISTEN'),('udp','udp','udp','UNCONN')]:
                rec=inet_row(proc[table],info[label]['inode']); port=info[label]['name'][1]
                selected=[r for r in rows if r['type']==want_type and r['state']==want_state and
                          r['local'].endswith(':'+str(port)) and r['rqueue']==str(rec['rx']) and r['wqueue']==str(rec['tx'])]
                if len(selected)!=1: failures.append(label+' proc row mismatch')
            for label,state in [('listener','LISTEN'),('accepted','ESTAB'),('client','ESTAB')]:
                name=byino[info[label]['inode']].get('name','*') or '*'
                selected=[r for r in rows if r['type']=='u_str' and r['state']==state and r['local']==name and r['rqueue']=='0' and r['wqueue']=='0']
                if len(selected)!=1: failures.append(label+' proc fallback row or zero queues mismatch')
            report.update(candidate_rows=rows,parse_error=error,denied_socket_count=len(requests),failures=failures)
        else: raise ValueError('unknown socket mode')
        save(mode+'.json',report)
        if failures: raise RuntimeError('candidate assertions failed: '+repr(failures))
        print(mode+'=ok')
    except Exception as exc:
        report['fatal_error']=str(exc);save(mode+'.json',report);raise
    finally:
        for s in sockets.values(): s.close()


def many_child(label):
    socks=[];identities=[]
    for i in range(90):
        name='nn-fixture-'+label+'-socket-name-'+str(i)
        s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.bind('\0'+name);socks.append(s)
        identities.append({'name':'@'+name,'fd':s.fileno(),'inode':os.fstat(s.fileno()).st_ino})
    print(json.dumps({'pid':os.getpid(),'sockets':identities}),flush=True)
    if sys.stdin.readline()!='done\n': raise RuntimeError('fixture child release missing')
    for s in socks: s.close()


def many(mode,binary=None):
    children=[]; report={'mode':mode,'children':[]}
    try:
        for i in range(8):
            proc=subprocess.Popen(['/usr/bin/python3',__file__,'many-child',str(i)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            info=json.loads(proc.stdout.readline())
            if info['pid']!=proc.pid: raise RuntimeError('socket child identity mismatch')
            info['status']=Path('/proc/%d/status'%proc.pid).read_text();info['stat']=Path('/proc/%d/stat'%proc.pid).read_text()
            children.append((proc,info));report['children'].append(info)
        diag=diag_unix();proc=raw_proc();native=run_process(['/usr/bin/ss','-axn'])
        report.update(netlink=diag,proc=proc,native=native)
        names=[v['name'] for _,info in children for v in info['sockets']]
        native_names=collections.Counter(r.get('name') for r in diag['records'])
        if len(diag['datagrams'])<2 or any(native_names[n]!=1 for n in names) or native['status']!=0:
            raise RuntimeError('multipart kernel/native control failed')
        native_text=bytes_out(native).decode('utf-8','replace')
        if any(sum(name in line.split() for line in native_text.splitlines())!=1 for name in names):
            raise RuntimeError('native ss did not render all fixture sockets')
        if mode=='many-control': save('many-control.json',report);return
        candidate=run_process(shell(binary,'[[ $(type -t ss) == builtin ]] || exit 99\nss -axn\n'));report['candidate']=candidate
        try: rows=parse_candidate(bytes_out(candidate),'ss'); error=None
        except ValueError as exc: rows=[];error=str(exc)
        counts=collections.Counter(r['local'] for r in rows if r['type']=='u_dgr')
        missing=[n for n in names if counts[n]!=1]
        report.update(candidate_rows=rows,parse_error=error,missing_or_duplicate=missing)
        save('many.json',report)
        if candidate['status']!=0 or error or missing: raise RuntimeError('multipart rows missing or duplicated')
        print('multipart=ok')
    except Exception as exc:
        report['fatal_error']=str(exc);save(mode+'.json',report);raise
    finally:
        for child,_ in children:
            if child.poll() is None:
                try: child.stdin.write('done\n');child.stdin.flush()
                except (BrokenPipeError,OSError): pass
        for child,_ in children:
            child.wait(timeout=5)
            if child.returncode!=0: raise RuntimeError('owned socket child failed to exit')


def main():
    guard();mode=sys.argv[1]
    if mode=='many-child': many_child(sys.argv[2])
    elif mode in ('control','unix','fallback'): simple(mode,sys.argv[2] if len(sys.argv)>2 else None)
    elif mode in ('many-control','many'): many(mode,sys.argv[2] if len(sys.argv)>2 else None)
    else: raise ValueError('unknown mode')


if __name__=='__main__': main()
