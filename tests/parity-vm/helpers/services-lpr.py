#!/usr/bin/python3
"""Guest-only print backend, owned witness and raw observation checker."""
import base64
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid


def require_guest():
    try:
        marker=Path('/etc/bashos-parity-vm').read_text().strip()
        case, home=Path('/tmp/parity-case'),Path('/tmp/parity-home')
        if (str(uuid.UUID(marker)) != marker.lower()
                or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or os.getuid()!=2000 or os.geteuid()!=2000
                or os.environ.get('HOME')!=str(home) or Path.cwd().resolve()!=case
                or case.stat().st_uid!=2000 or home.stat().st_uid!=2000):
            raise ValueError('guest identity or scratch mismatch')
    except (OSError,ValueError) as exc:
        raise SystemExit('requires disposable parity guest: '+str(exc))


HOME=Path('/tmp/parity-home')
CASE=Path('/tmp/parity-case')
EXPECTED=b'print fixture\n\x00\xffsecond line\n'


def append(name, obj):
    with (HOME/name).open('a') as f: f.write(json.dumps(obj,sort_keys=True)+'\n')


def backend():
    if len(sys.argv)!=4:
        raise SystemExit('expected ID SIZE TITLE')
    mode=os.environ.get('LPR_FIXTURE_MODE','')
    if mode not in ('control','file','stdin','barefile','barestdin','partial','failure','timeout','cancel'):
        raise SystemExit('unexpected backend mode')
    data=b''
    while True:
        chunk=os.read(0, 3 if mode=='partial' else 65536)
        data+=chunk
        if not chunk or mode=='partial': break
    try: offset=os.lseek(0,0,os.SEEK_CUR)
    except OSError: offset=None
    event={'kind':'start','mode':mode,'argv':sys.argv,'pid':os.getpid(),'ppid':os.getppid(),
           'pgid':os.getpgrp(),'bytes_base64':base64.b64encode(data).decode(),
           'offset':offset,'time_monotonic':time.monotonic()}
    append(mode+'.events',event)
    (HOME/(mode+'.data')).write_bytes(data)
    if mode in ('timeout','cancel'):
        def on_term(sig, frame):
            append(mode+'.events',{'kind':'signal','signal':sig,'pid':os.getpid(),'time_monotonic':time.monotonic()})
            raise SystemExit(42)
        signal.signal(signal.SIGTERM,on_term)
        (HOME/(mode+'.ready')).write_text(sys.argv[1]+'\n')
        until=time.monotonic()+10
        while time.monotonic()<until: time.sleep(.05)
        append(mode+'.events',{'kind':'expired','pid':os.getpid()})
        return 9
    return 7 if mode=='failure' else 0


def witness():
    def receive(sig, frame): append('witness.events',{'kind':'signal','signal':sig,'pid':os.getpid()})
    signal.signal(signal.SIGTERM,receive); signal.signal(signal.SIGINT,receive); signal.signal(signal.SIGHUP,receive)
    append('witness.events',{'kind':'start','pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp()})
    (HOME/'witness.ready').write_text(str(os.getpid())+'\n')
    until=time.monotonic()+20
    while not (HOME/'witness.stop').exists() and time.monotonic()<until: time.sleep(.05)
    append('witness.events',{'kind':'stop','pid':os.getpid()})
    return 0


def read_events(mode):
    try: return [json.loads(line) for line in (HOME/(mode+'.events')).read_text().splitlines()]
    except (OSError,ValueError): return []


def check(mode, owner=None):
    events=read_events(mode)
    e=events[0] if events else {}
    job_id=e.get('argv',['',''])[1] if len(e.get('argv',[]))==4 else ''
    data=b'ABCDEF' if mode=='control' else EXPECTED
    received=data[:3] if mode=='partial' else data
    title={'control':'proof','file':'file with space','stdin':'stdin','barefile':'file with space',
           'barestdin':'stdin','partial':'file with space','failure':'file with space',
           'timeout':'file with space','cancel':'file with space'}[mode]
    try: actual_data=(HOME/(mode+'.data')).read_bytes()
    except OSError: actual_data=None
    ok=(len(events)>=1 and e.get('kind')=='start' and e.get('mode')==mode
        and bool(re.fullmatch('[0-9a-f]{16}',job_id))
        and e.get('argv')==[str(HOME/'backend'),job_id,str(len(data)),title]
        and e.get('bytes_base64')==base64.b64encode(received).decode()
        and actual_data==received)
    if mode!='control':
        out=(HOME/(mode+'.out')).read_text(errors='replace') if (HOME/(mode+'.out')).exists() else ''
        err=(HOME/(mode+'.err')).read_text(errors='replace') if (HOME/(mode+'.err')).exists() else ''
        prefix='lpr: spooled '+str(HOME/'spool')+'/'+job_id+'.lpr\n'
        ok &= out.startswith(prefix)
        if mode in ('file','stdin','barefile','barestdin'):
            ok &= out==prefix+f'lpr: accepted {job_id} ({len(data)} bytes)\n' and err==''
        if mode=='partial': ok &= f'backend exited 0 after consuming 3 of {len(data)} bytes' in err
        if mode=='failure': ok &= 'backend exited with status 7' in err
        if mode=='timeout': ok &= 'backend timed out after 1 s' in err
        if mode=='cancel':
            ok &= 'lpr: cancelled '+job_id in err and owner is not None and e.get('ppid')==owner
        if mode in ('timeout','cancel'):
            ok &= len(events)==2 and events[1].get('kind')=='signal' and events[1].get('signal')==signal.SIGTERM and events[1].get('pid')==e.get('pid')
        spool=HOME/'spool'
        ok &= spool.is_dir() and list(spool.iterdir())==[]
    print(mode+'-observation='+('ok' if ok else 'BAD'))


def check_witness():
    events=read_events('witness')
    ok=(len(events)==2 and events[0].get('kind')=='start' and events[1].get('kind')=='stop'
        and events[0].get('pid')==events[1].get('pid'))
    print('witness-observation='+('ok' if ok else 'BAD'))


if __name__=='__main__':
    require_guest()
    if len(sys.argv)==2 and sys.argv[1]=='--witness':
        raise SystemExit(witness())
    if len(sys.argv) in (3,4) and sys.argv[1]=='--check':
        if sys.argv[2]=='witness': check_witness()
        else: check(sys.argv[2], int(sys.argv[3]) if len(sys.argv)==4 else None)
    else:
        raise SystemExit(backend())
