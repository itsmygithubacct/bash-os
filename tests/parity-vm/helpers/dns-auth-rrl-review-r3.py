#!/usr/bin/env python3
"""Read retained burst and owned-server records; no subject code imported."""
import json, os, re, struct, sys, uuid
from pathlib import Path
def guard():
    marker=Path('/etc/bashos-parity-vm').read_text().strip(); uuid.UUID(marker)
    if (Path('/run/bashos-parity-vm-identity').read_text().strip().lower()!=marker.lower() or
        Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or
        os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=Path('/tmp/parity-case') or
        os.environ.get('HOME')!='/tmp/parity-home'):
        raise RuntimeError('not the unprivileged disposable guest')
guard()
h=Path('/tmp/parity-home'); result={'candidate_failures':[],'infrastructure':[],'modes':{}}
def readlines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]
def inspect(mode):
    events=readlines(h/('rrl-'+mode+'-events.jsonl')); ident=next((x for x in events if x['event']=='identity'),None)
    done=next((x for x in events if x['event']=='observer-complete'),None)
    if not ident or not ident['candidate_exe_matches'] or set(ident['listeners'])!={'tcp','udp'} or not done:
        result['infrastructure'].append(mode+': missing identity or completed observer');return
    send=[x for x in events if x['event']=='send']; recv=[x for x in events if x['event']=='receive']
    log=(h/('rrl-'+mode+'.server.log')).read_text(errors='replace')
    m=re.search(r'queries=(\d+).*rrl-dropped=(\d+) rrl-truncated=(\d+)',log)
    cleanup=json.loads((h/('rrl-'+mode+'-cleanup.json')).read_text())
    if len(send)!=20 or any(x['bytes']!=len(bytes.fromhex(x['hex'])) for x in send) or not m:
        result['infrastructure'].append(mode+': incomplete sends or server summary');return
    count,drops,trunc=map(int,m.groups());byid={}
    for x in recv:
        if 'id' in x and x['id'] not in byid: byid[x['id']]=x
    duration=done['last_send_ns']-done['first_send_ns']; exit_ns=done['server_exit_observed_ns']
    qualified=count==20 and exit_ns is not None and 0<=exit_ns-done['first_send_ns']<900_000_000 and duration<900_000_000
    if cleanup['observer_status']!=0 or cleanup['server_status']!=0 or cleanup['pending_cleanup']:
        result['infrastructure'].append(mode+': observer or cleanup failed')
    result['modes'][mode]={'server_queries':count,'server_drops':drops,'server_truncated':trunc,'burst_ns':duration,'server_exit_after_first_ns':None if exit_ns is None else exit_ns-done['first_send_ns'],'received_ids':sorted(byid),'qualified':qualified,'cleanup':cleanup}
    if not qualified:
        result['infrastructure'].append(mode+': timing, reception count or cleanup incomplete');return
    # Timing, owned server and summary bind all sent datagrams to this burst;
    # independent received IDs determine cadence. Missing packets are interpreted
    # as drops only with the paired no-RRL positive transport control.
    return byid,drops,trunc
try:
    for mode in ('control','limited'):
        failure=h/('rrl-'+mode+'-reached-failures.jsonl')
        if failure.exists():
            try:
                for line_no, line in enumerate(failure.read_text().splitlines(),1):
                    try: result['candidate_failures'].append(json.loads(line))
                    except json.JSONDecodeError:
                        result['infrastructure'].append(mode+': malformed reached record line '+str(line_no))
            except OSError as exc:
                result['infrastructure'].append(mode+': reached record unavailable: '+repr(exc))
    values={}
    for mode in ('control','limited'):
        try: values[mode]=inspect(mode)
        except Exception as exc:
            values[mode]=None; result['infrastructure'].append(mode+': review exception: '+repr(exc))
    control=values['control'];limited=values['limited']
    if control and limited:
        co,cd,ct=control; li,ld,lt=limited
        if len(co)!=20 or cd or ct or any(x.get('flags',0)&0x200 for x in co.values()):
            result['infrastructure'].append('no-RRL positive control failed; cannot attribute absent limited responses')
        elif len(li)!=20-ld or sum(bool(x.get('flags',0)&0x200) for x in li.values())!=lt:
            result['infrastructure'].append('limited wire counts disagree with server summary; missing replies unattributed')
        else:
            for i in range(20):
                ident=0x6100+i; got=li.get(ident); expected='full' if i==0 else ('drop' if i%2 else 'tc')
                actual='drop' if got is None else ('tc' if got.get('flags',0)&0x200 else 'full')
                if actual!=expected: result['candidate_failures'].append({'mode':'limited','id':ident,'expected':expected,'actual':actual})
            # Summary is a cross-check, not the source of the per-ID verdict.
            if ld!=10 or lt!=9:result['infrastructure'].append('server summary does not corroborate drop/slip accounting')
except Exception as exc:result['infrastructure'].append('review exception: '+repr(exc))
with (h/'rrl-review.json').open('w') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
if result['candidate_failures']:print('candidate=FAIL');sys.exit(1)
if result['infrastructure']:print('observer=incomplete');sys.exit(125)
print('rrl=PASS control=PASS cadence=PASS')
