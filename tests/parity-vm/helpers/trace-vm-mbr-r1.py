#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent bounded MBR decoder for a scratch regular-file image."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text('ascii').strip()
        if str(uuid.UUID(marker))!=marker.lower(): raise ValueError('invalid VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text('ascii').strip()!='QEMU': raise ValueError('not QEMU')
        if os.getuid()!=2000 or os.geteuid()!=2000: raise ValueError('wrong uid')
        if Path.cwd()!=Path('/tmp/parity-case') or os.environ.get('HOME')!='/tmp/parity-home': raise ValueError('wrong scratch directory')
    except (OSError,ValueError,UnicodeError) as exc:
        raise SystemExit('refusing outside disposable parity VM: '+str(exc))


require_guest()
HOME=Path('/tmp/parity-home')


def decode(raw):
    if len(raw)!=512: raise ValueError('wrong sector length')
    entries=[]
    for i in range(4):
        data=raw[446+16*i:462+16*i]
        boot,chs_first,typ,chs_last,start,count=struct.unpack('<B3sB3sII',data)
        entries.append({'boot':boot,'type':typ,'start':start,'sectors':count,
                        'chs_first_hex':chs_first.hex(),'chs_last_hex':chs_last.hex(),'raw_hex':data.hex()})
    return {'signature_hex':raw[510:512].hex(),'entries':entries}


def matches(d, boot, typ, start, count):
    first=d['entries'][0]
    return (d['signature_hex']=='55aa' and [first['boot'],first['type'],first['start'],first['sectors']]==[boot,typ,start,count]
            and all(e['raw_hex']=='00'*16 for e in d['entries'][1:]))


def save(name,data):
    (HOME/name).write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')


def control():
    block=bytearray(512)
    struct.pack_into('<B3sB3sII',block,446,0x80,b'\0'*3,0x0c,b'\0'*3,2048,1024)
    block[510:512]=b'\x55\xaa'
    good=decode(block)
    bad=bytearray(block);bad[446]=0
    checks={'expected':matches(good,0x80,0x0c,2048,1024),
            'reject_bad_boot':not matches(decode(bad),0x80,0x0c,2048,1024),
            'reject_bad_signature':not matches(decode(block[:510]+b'\0\0'),0x80,0x0c,2048,1024)}
    save('mbr-control.json',{'sector_base64':base64.b64encode(block).decode(),'decoded':good,'checks':checks})
    if not all(checks.values()): raise AssertionError('MBR decoder control failed')
    print('mbr controls ok')


def observe(mode):
    p=Path('disk.img')
    info=p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size!=2*1024*1024: raise ValueError('unexpected fixture image')
    data=p.read_bytes(); sector=data[:512]; parsed=decode(sector)
    record={'mode':mode,'size':info.st_size,'sha256':hashlib.sha256(data).hexdigest(),
            'sector0_base64':base64.b64encode(sector).decode(),'decoded':parsed,
            'remaining_bytes_all_zero':not any(data[512:]),'image_all_zero':not any(data)}
    if mode=='blank': ok=record['image_all_zero']
    elif mode=='edited': ok=record['remaining_bytes_all_zero'] and matches(parsed,0x80,0x0c,2048,1024)
    elif mode=='default': ok=record['remaining_bytes_all_zero'] and matches(parsed,0,0x83,2048,2048)
    else: raise ValueError('unknown mode')
    record['expected_result']=ok
    save('mbr-observation.json',record)
    if not ok: raise AssertionError('MBR image does not match expected bytes/fields')
    print(mode+' image ok')


if sys.argv[1:]==['--control']: control()
elif len(sys.argv)==2 and sys.argv[1] in ('blank','edited','default'): observe(sys.argv[1])
else: raise SystemExit('invalid invocation')
