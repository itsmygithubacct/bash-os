#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Controls and log checks for isolated guest socket and argument fixtures."""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import struct
import sys
import uuid

HOME = Path('/tmp/parity-home')


def guard():
    marker = Path('/etc/bashos-parity-vm').read_text().strip()
    uuid.UUID(marker)
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
            or os.getuid() != 2000 or os.geteuid() != 2000
            or Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != str(HOME)):
        raise RuntimeError('disposable guest identity mismatch')
    virt = subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,
                          text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'):
        raise RuntimeError('not a QEMU/KVM guest')


def save(name, value):
    (HOME/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def control(mode):
    if mode=='devfull':
        fd=os.open('/dev/full',os.O_WRONLY)
        try:
            try: os.write(fd,b'x'); result={'errno':0}
            except OSError as exc: result={'errno':exc.errno,'message':exc.strerror}
        finally: os.close(fd)
        save('full-control.json',result)
        if result['errno']!=errno.ENOSPC: raise RuntimeError('/dev/full does not return ENOSPC')
    elif mode=='diag-ok':
        request={'family':socket.AF_NETLINK,'type':socket.SOCK_RAW,'protocol':4}
        with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
            s.bind((0,0)); result={'request':request,'fd':s.fileno(),'bound':s.getsockname(),
                                  'network_namespace':os.readlink('/proc/self/ns/net')}
        result['proc_tables'] = {}
        for name in ('tcp', 'tcp6', 'udp', 'udp6', 'unix'):
            path = Path('/proc/net') / name
            if path.exists():
                data = path.read_text()
                if len(data) > 512 * 1024:
                    raise RuntimeError('proc table evidence exceeds bound')
                result['proc_tables'][name] = data
        save('diag-control.json',result)
    elif mode=='diag-denied':
        request={'family':socket.AF_NETLINK,'type':socket.SOCK_RAW,'protocol':4}
        try:
            with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4): pass
            result={'request':request,'errno':0}
        except OSError as exc:
            result={'request':request,'errno':exc.errno,'message':exc.strerror}
        save('diag-denied-control.json',result)
        if result['errno']!=errno.EPERM: raise RuntimeError('diag socket was not denied EPERM')
    elif mode=='icmp-denied':
        request={'family':socket.AF_INET,'type':socket.SOCK_DGRAM,'protocol':socket.IPPROTO_ICMP}
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP): pass
            result={'request':request,'errno':0}
        except OSError as exc:
            result={'request':request,'errno':exc.errno,'message':exc.strerror}
        save('icmp-control.json',result)
        if result['errno']!=errno.EACCES: raise RuntimeError('ICMP socket was not denied EACCES')
    elif mode=='resolver':
        Path('mark-resolve-start').read_text()
        reply=socket.getaddrinfo('localhost',80,socket.AF_INET,socket.SOCK_STREAM)
        Path('mark-resolve-end').read_text()
        result={'query':'localhost','results':[list(x[:4])+[list(x[4])] for x in reply]}
        save('resolver-control.json',result)
        if not any(x[4][0].startswith('127.') for x in reply):
            raise RuntimeError('localhost did not resolve to loopback')
    else:
        raise ValueError('unknown control')


def records(name):
    items = [json.loads(line) for line in (HOME/name).read_text().splitlines() if line]
    for row in items:
        request, response = bytes.fromhex(row['request_hex']), bytes.fromhex(row['response_hex'])
        if len(request) != 80 or len(response) != 24 or row.get('response_status') != 'sent':
            raise RuntimeError('invalid or unsent notification transcript')
        ident, pid, flags, nr, arch, ip = struct.unpack_from('<QIIiIQ', request)
        values = list(struct.unpack_from('<6Q', request, 32))
        response_id, value, error, response_flags = struct.unpack('<QqiI', response)
        if (ident, pid, nr, arch, ip, values, ident) != (row['id'], row['pid'], row['syscall_number'], row['arch'], row['instruction_pointer'], row['args'], response_id):
            raise RuntimeError('notification raw/decoded mismatch')
        if row['reply'].startswith('errno:') and (error != -int(row['reply'].split(':')[1]) or response_flags != 0):
            raise RuntimeError('errno response does not match bytes')
        if row['reply'] == 'continue' and (error != 0 or response_flags != 1):
            raise RuntimeError('continue response does not match bytes')
    return items


def interval(items, tag):
    def ismark(row, suffix):
        return row.get('syscall')=='openat' and row.get('string1')=='mark-'+tag+'-'+suffix
    starts=[i for i,x in enumerate(items) if ismark(x,'start')]
    ends=[i for i,x in enumerate(items) if ismark(x,'end')]
    if len(starts)!=1 or len(ends)!=1 or starts[0]>=ends[0]:
        raise RuntimeError('missing or ambiguous observer interval '+tag)
    return items[starts[0]+1:ends[0]]


def check(mode, name):
    items=records(name)
    if mode=='resolver-control':
        data=interval(items,'resolve')
        paths={r.get('string1') for r in data if r.get('syscall')=='openat'}
        watched={'/etc/hosts','/etc/nsswitch.conf','/etc/resolv.conf','/etc/gai.conf'}
        if not (paths & watched):
            raise RuntimeError('positive resolver control did not expose an NSS file open')
    elif mode=='quiet':
        data=interval(items,'invalid')
        watched={'/etc/hosts','/etc/nsswitch.conf','/etc/resolv.conf','/etc/gai.conf'}
        offenders=[r for r in data if r.get('syscall') in ('socket','connect') or
                   (r.get('syscall')=='openat' and r.get('string1') in watched)]
        save('invalid-observation.json',{'requests':len(data),'offenders':offenders})
        if offenders: raise RuntimeError('invalid option attempted socket/connect or resolver file access')
        print('observer=quiet')
    elif mode=='icmp':
        summary={}
        for tag in ('min','max'):
            data=interval(items,tag)
            hits=[r for r in data if r.get('syscall')=='socket' and r['args'][0]==socket.AF_INET
                  and r['args'][2]==socket.IPPROTO_ICMP and r.get('reply')=='errno:13']
            summary[tag]=len(hits)
        save('icmp-observation.json',summary)
        if not all(summary.values()): raise RuntimeError('endpoint did not reach denied ICMP socket request')
        print('endpoint-sockets=observed-and-denied')
    elif mode=='diag':
        hits=[r for r in items if r.get('syscall')=='socket' and r['args'][0]==socket.AF_NETLINK
              and r['args'][2]==4 and r.get('reply')=='errno:1']
        save('diag-observation.json',{'denied_requests':len(hits)})
        if len(hits)<2: raise RuntimeError('diag socket denial was not observed for repeated versions')
        print('diag-denial=observed')
    elif mode=='diag-control':
        hits=[r for r in items if r.get('syscall')=='socket' and r['args'][0]==socket.AF_NETLINK
              and r['args'][2]==4 and r.get('reply')=='errno:1']
        if not hits: raise RuntimeError('diag denial control not observed')
    elif mode=='icmp-control':
        hits=[r for r in items if r.get('syscall')=='socket' and r['args'][0]==socket.AF_INET
              and r['args'][2]==socket.IPPROTO_ICMP and r.get('reply')=='errno:13']
        if not hits: raise RuntimeError('ICMP denial control not observed')
    else:
        raise ValueError('unknown check')


def main():
    guard()
    if sys.argv[1]=='control': control(sys.argv[2])
    elif sys.argv[1]=='check': check(sys.argv[2],sys.argv[3])
    else: raise ValueError('unknown mode')


if __name__=='__main__':
    main()
