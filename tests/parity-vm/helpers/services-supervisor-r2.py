#!/usr/bin/python3
"""VM-only service-tree builder, service/finish/probe and evidence checker."""
import base64
import ctypes
import errno
import json
import os
import select
import struct
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

HOME=Path('/tmp/parity-home'); CASE=Path('/tmp/parity-case'); EVENTS=HOME/'sv.events'

def guard():
    try:
        m=Path('/etc/bashos-parity-vm').read_text().strip()
        if (str(uuid.UUID(m))!=m.lower() or Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU'
            or os.getuid()!=2000 or os.geteuid()!=2000 or os.environ.get('HOME')!=str(HOME)
            or Path.cwd().resolve()!=CASE or CASE.stat().st_uid!=2000 or HOME.stat().st_uid!=2000):
            raise ValueError('guest identity or private scratch mismatch')
    except (OSError,ValueError) as exc: raise SystemExit('requires disposable guest: '+str(exc))


def event(name,kind,**fields):
    d={'name':name,'kind':kind,'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp(),'proc_starttime':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),'time':time.monotonic(),**fields}
    data=(json.dumps(d,sort_keys=True)+'\n').encode()
    fd=os.open(EVENTS,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try: os.write(fd,data)
    finally: os.close(fd)


def probe(name):
    event(name,'probe-start')
    for _ in range(160):
        if (HOME/('gate.'+name)).exists() and ((HOME/('started.'+name)).exists() or name=='control'):
            event(name,'probe-ok'); return 0
        time.sleep(.05)
    event(name,'probe-timeout'); return 1


def proc_identity(pid):
    """Read PID identity only inside the guest; preserve raw identity for audit."""
    try:
        root=Path('/proc')/str(pid)
        raw=(root/'stat').read_text()
        fields=raw.rsplit(')',1)[1].split()
        return {'pid':pid,'uid':root.stat().st_uid,'state':fields[0],
                'ppid':int(fields[1]),'pgid':int(fields[2]),'session':int(fields[3]),
                'starttime':int(fields[19]),'stat':raw.strip(),
                'cmdline_hex':(root/'cmdline').read_bytes()[:4096].hex()}
    except (OSError,ValueError,IndexError): return None


def append_json(name, data):
    with (HOME/name).open('a') as f: f.write(json.dumps(data,sort_keys=True)+'\n')


def reap_fixture_child(name,child,birth):
    """Never block indefinitely, and never target a PID without identity proof."""
    before=proc_identity(child)
    event(name,'child-cleanup-pre',child=child,birth=birth,observation=before)
    forced=False
    def try_reap():
        try: return os.waitpid(child,os.WNOHANG)
        except ChildProcessError: return (-1,0)
        except InterruptedError: return (0,0)
    until=time.monotonic()+1.5
    while time.monotonic()<until:
        pid,status=try_reap()
        if pid==child:
            event(name,'child-reaped',child=pid,status=status,forced=False); return True
        if pid<0:
            event(name,'child-reap-error',child=child,error='not a child'); return False
        time.sleep(.025)
    current=proc_identity(child)
    eligible=(birth is not None and current is not None and current['uid']==2000
              and current['starttime']==birth and current['ppid']==os.getpid()
              and current['pgid']==os.getpgrp() and current['state']!='Z')
    event(name,'child-cleanup-decision',child=child,eligible=eligible,observation=current)
    if eligible:
        # Verify again immediately before signalling the exact fixture-owned child.
        latest=proc_identity(child)
        if latest and latest['starttime']==birth and latest['ppid']==os.getpid() and latest['pgid']==os.getpgrp() and latest['uid']==2000:
            try: os.kill(child,signal.SIGKILL); forced=True
            except ProcessLookupError: pass
    if forced: event(name,'child-forced-cleanup',child=child,signal=signal.SIGKILL)
    until=time.monotonic()+2
    while time.monotonic()<until:
        pid,status=try_reap()
        if pid==child:
            event(name,'child-reaped',child=pid,status=status,forced=forced); return True
        if pid<0:
            event(name,'child-reap-error',child=child,error='not a child'); return False
        time.sleep(.025)
    event(name,'child-unreaped',child=child,forced=forced,observation=proc_identity(child))
    return False


def normal_child_cleanup(events,name):
    starts=[x for x in events if x.get('name')==name and x.get('kind')=='start']
    children=[x for x in events if x.get('name')==name and x.get('kind')=='child-start']
    signals=[x for x in events if x.get('name')==name and x.get('kind')=='child-signal']
    reaped=[x for x in events if x.get('name')==name and x.get('kind')=='child-reaped']
    forced=[x for x in events if x.get('name')==name and x.get('kind') in ('child-forced-cleanup','child-unreaped','child-reap-error')]
    exits=[x for x in events if x.get('name')==name and x.get('kind')=='exit']
    parent_signals=[x for x in events if x.get('name')==name and x.get('kind')=='signal']
    return (len(starts)==len(children)==len(reaped)==1 and not forced
            and children[0]['ppid']==starts[0]['pid'] and reaped[0].get('child')==children[0]['pid']
            and reaped[0].get('pid')==starts[0]['pid'] and reaped[0].get('forced') is False
            and len(exits)==1 and exits[0].get('pid')==starts[0]['pid'] and exits[0].get('expired') is False
            and any(x.get('pid')==starts[0]['pid'] and x.get('number')==signal.SIGTERM for x in parent_signals)
            and any(x.get('pid')==children[0]['pid'] and x.get('number')==signal.SIGTERM
                    and x.get('owner_alive') is True for x in signals))


def run(name,config):
    kind=config['kind']
    event(name,'start',argv=sys.argv,sv_name=os.environ.get('SV_NAME'))
    if kind in ('exit0','exit7','oneshot'):
        rc=7 if kind=='exit7' else 0
        event(name,'exit',status=rc); return rc
    if kind=='window':
        countfile=HOME/('count.'+name)
        try: count=int(countfile.read_text())+1
        except (OSError,ValueError): count=1
        countfile.write_text(str(count)+'\n')
        if count<3:
            event(name,'exit',status=0); return 0
    if kind=='socket':
        data={'listen_fds':os.environ.get('LISTEN_FDS'),'listen_pid':os.environ.get('LISTEN_PID'),'listen_fdnames':os.environ.get('LISTEN_FDNAMES')}
        try:
            s=socket.socket(fileno=3); data['accepting']=s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN); data['address']=s.getsockname(); s.settimeout(4)
            c,peer=s.accept(); data['peer']=peer; data['request_hex']=c.recv(128).hex(); c.sendall(b'pong'); c.close()
        except OSError as exc: data['error']=str(exc)
        event(name,'socket',**data); event(name,'exit',status=0); return 0
    done=False
    def handler(sig,frame):
        nonlocal done
        event(name,'signal',number=sig)
        if sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT): done=True
    for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT,signal.SIGUSR1): signal.signal(sig,handler)
    child=None; birth=None; expired=False; reaped=True
    try:
        if kind in ('tree','notify'):
            owner=os.getpid(); child=os.fork()
            if child==0:
                def child_term(sig, frame):
                    event(name,'child-signal',number=sig,owner_alive=(os.getppid()==owner)); os._exit(0)
                signal.signal(signal.SIGTERM,child_term)
                libc=ctypes.CDLL(None,use_errno=True)
                if libc.prctl(1,signal.SIGTERM,0,0,0)!=0:
                    event(name,'child-watchdog-error',errno=ctypes.get_errno()); os._exit(87)
                if os.getppid()!=owner:
                    event(name,'child-parent-gone',owner=owner); os._exit(88)
                event(name,'child-start')
                (HOME/'child-ready').write_text(str(os.getpid())+'\n')
                until=time.monotonic()+18
                while time.monotonic()<until:
                    if os.getppid()!=owner:
                        event(name,'child-parent-gone',owner=owner); os._exit(89)
                    time.sleep(.05)
                event(name,'child-watchdog-expired',owner=owner); os._exit(90)
            identity=proc_identity(child)
            birth=identity['starttime'] if identity else None
            for _ in range(100):
                if (HOME/'child-ready').exists(): break
                time.sleep(.02)
        (HOME/('started.'+name)).write_text(str(os.getpid())+'\n')
        if kind=='notify':
            address=os.environ.get('NOTIFY_SOCKET','')
            stages=[('ready',lambda: f'READY=1\nSTATUS=fixture-ready\nMAINPID={child}'.encode()),
                    ('reload',lambda: b'RELOADING=1\nSTATUS=fixture-reloading'),
                    ('stopping',lambda: b'STOPPING=1\nSTATUS=fixture-stopping')]
        else: stages=[]
        seen=set(); end=time.monotonic()+14
        while not done and time.monotonic()<end:
            for stage,message in stages:
                if stage not in seen and (HOME/('notify.'+stage)).exists():
                    wire=message(); sock=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
                    target=('\0'+address[1:]) if address.startswith('@') else address
                    try: sock.sendto(wire,target); event(name,'notify',wire_hex=wire.hex(),target=address)
                    except OSError as exc: event(name,'notify-error',error=str(exc))
                    finally: sock.close()
                    seen.add(stage)
            time.sleep(.05)
        expired=not done
    finally:
        if child is not None and child>0: reaped=reap_fixture_child(name,child,birth)
    event(name,'exit',status=0 if reaped else 1,expired=expired)
    return 0 if reaped else 1


def setup(scenario):
    common={'control':{'kind':'exit7','directives':[]}}
    scenarios={
      'once':{'once':{'kind':'exit7','directives':[]}},
      'oneshot':{'onceup':{'kind':'oneshot','directives':['type: oneshot']}},
      'life':{'life':{'kind':'long','directives':['restart: never']}},
      'run':{'life':{'kind':'tree','directives':['restart: never']}},
      'window':{'window':{'kind':'window','directives':['restart: always','restart-max: 1','restart-window: 1','restart-delay: 2']}},
      'probe':{'a_probe':{'kind':'long','directives':['readiness: ./check','readiness-timeout: 4']},
                 'z_dependent':{'kind':'long','directives':['requires: a_probe']}},
      'order':{
        'zbase':{'kind':'long','directives':['before: mbefore','readiness: ./check']},
        'mbefore':{'kind':'long','directives':['readiness: ./check']},
        'ayrequires':{'kind':'long','directives':['requires: mbefore','readiness: ./check']},
        'bafter':{'kind':'long','directives':['after: ayrequires','readiness: ./check']}},
      'restart':{
        'always':{'kind':'exit0','directives':['restart: always','restart-max: 2','restart-window: 60','restart-delay: 1']},
        'failure':{'kind':'exit7','directives':['restart: on-failure','restart-max: 2','restart-window: 60','restart-delay: 1']},
        'success':{'kind':'exit0','directives':['restart: on-failure','restart-max: 2','restart-window: 60','restart-delay: 1']},
        'never':{'kind':'exit7','directives':['restart: never','restart-max: 2','restart-window: 60','restart-delay: 1']}},
      'timeout':{'a_probe':{'kind':'long','directives':['readiness: ./check','readiness-timeout: 1']},
                 'z_dependent':{'kind':'long','directives':['requires: a_probe']}},
      'command':{'a_command':{'kind':'long','directives':['readiness: /tmp/parity-home/sv-helper --probe a_command','readiness-timeout: 4']},
                 'z_dependent':{'kind':'long','directives':['requires: a_command']}},
      'notify':{'a_notify':{'kind':'notify','directives':['readiness: notify','readiness-timeout: 5','restart: never']},
                'z_dependent':{'kind':'long','directives':['requires: a_notify']}},
      'socket':{'socket':{'kind':'socket','directives':[]}},
      'path':{'path':{'kind':'exit0','directives':[]}},
    }
    configs=scenarios[scenario]; allconf={**configs,**common}
    (HOME/'services').mkdir(); (HOME/'state').mkdir(); (HOME/'logs').mkdir()
    (HOME/'control').mkdir()
    (HOME/'svconfig.json').write_text(json.dumps(allconf,indent=2)+'\n')
    source=Path('/opt/bashos-parity/harness/helpers/services-supervisor-r2.py').read_text().split('\n',1)[1]
    for name,c in allconf.items():
        folder=(HOME/'control'/name) if name=='control' else (HOME/'services'/name)
        folder.mkdir()
        entries=['run','finish']
        if name=='control' or 'readiness: ./check' in c['directives']: entries.append('check')
        for entry in entries:
            directives=''.join('# '+v+'\n' for v in c['directives']) if entry=='run' else ''
            path=folder/entry; path.write_text('#!/usr/bin/python3\n'+directives+source); path.chmod(0o700)
        if scenario=='order': (HOME/('gate.'+name)).write_text('go\n')
    # A standalone run, finish and readiness probe prove the adapter and trace protocol.
    (HOME/'gate.control').write_text('go\n')
    p=subprocess.run([str(HOME/'control/control/run')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
    q=subprocess.run([str(HOME/'control/control/finish'),'7'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
    r=subprocess.run([str(HOME/'control/control/check')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
    data=read_events()
    if p.returncode!=7 or q.returncode!=0 or r.returncode!=0 or [x['kind'] for x in data]!=['start','exit','finish','probe-start','probe-ok']:
        raise SystemExit('CONTROL-FAILED service adapters')
    (HOME/'control.events').write_bytes(EVENTS.read_bytes()); EVENTS.write_text('')


def read_events():
    try:return [json.loads(x) for x in EVENTS.read_text().splitlines()]
    except (OSError,ValueError):return []


def safe_tree(required=None):
    events=read_events(); found=set(); observations=[]; ok=True
    for path in sorted((HOME/'state').glob('*/pid')):
        name=path.parent.name
        try:
            pid=int(path.read_text().strip()); info=Path('/proc')/str(pid)
            fields=(info/'stat').read_text().rsplit(')',1)[1].split()
            matches=[x for x in events if x.get('name')==name and x.get('pid')==pid and x.get('kind') in ('start','child-start')]
            current=matches[-1] if matches else {}
            starts=[x for x in events if x.get('name')==name and x.get('kind')=='start']
            valid=(bool(matches) and bool(starts) and fields[0]!='Z' and info.stat().st_uid==2000
                   and int(fields[19])==current.get('proc_starttime') and int(fields[2])==starts[-1]['pid']
                   and str(HOME/'services'/name/'run').encode() in (info/'cmdline').read_bytes())
            observations.append({'name':name,'pid':pid,'state':fields[0],'pgid':int(fields[2]),'starttime':int(fields[19]),'valid':valid})
            ok &= valid; found.add(name)
        except (OSError,ValueError,IndexError) as exc:
            observations.append({'name':name,'error':str(exc)});ok=False
    if required is not None: ok &= required in found
    with (HOME/'ownership.jsonl').open('a') as f: f.write(json.dumps({'required':required,'observations':observations,'ok':ok})+'\n')
    return 0 if ok else 1



def require_subreaper():
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(36,1,0,0,0)!=0:
        raise RuntimeError('subreaper unavailable: errno %s' % ctypes.get_errno())


def live_processes(root_pid,root_start,exclude=()):
    """Only descendants/adopted children of our verified subreaper are eligible."""
    root=proc_identity(root_pid)
    if not root or root['uid']!=2000 or root['starttime']!=root_start:
        raise RuntimeError('fixture subreaper identity changed')
    processes={}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit(): continue
        item=proc_identity(int(path.name))
        if item and item['uid']==2000: processes[item['pid']]=item
    descendants={root_pid}; changed=True
    while changed:
        changed=False
        for pid,item in processes.items():
            if pid not in descendants and item['ppid'] in descendants:
                descendants.add(pid); changed=True
    return sorted((processes[pid] for pid in descendants if pid in processes
                   and pid!=root_pid and pid not in exclude and processes[pid]['state']!='Z'),
                  key=lambda x:x['pid'])


def signal_verified(item,root_pid,root_start,signo):
    # PID/starttime/uid and a live ancestry chain must still match immediately
    # before a signal; a recycled PID or an unrelated same-UID session is refused.
    current=proc_identity(item['pid'])
    owned={x['pid']:x for x in live_processes(root_pid,root_start)}
    proof=owned.get(item['pid'])
    ok=(current is not None and proof is not None and current['uid']==2000
        and current['state']!='Z' and current['starttime']==item['starttime']
        and proof['starttime']==item['starttime'])
    result={'pid':item['pid'],'signal':int(signo),'matched':ok,'before':current}
    if ok:
        try: os.kill(item['pid'],signo); result['sent']=True
        except ProcessLookupError: result['sent']=False
        except OSError as exc: result['sent']=False; result['error']=str(exc)
    return result


def bounded_session_cleanup(root_pid,root_start,excluded=()):
    before=live_processes(root_pid,root_start,excluded)
    result={'root_pid':root_pid,'root_starttime':root_start,'before':before,'term':[],'kill':[],'remaining':[]}
    for item in before: result['term'].append(signal_verified(item,root_pid,root_start,signal.SIGTERM))
    until=time.monotonic()+1.5
    while time.monotonic()<until:
        if not live_processes(root_pid,root_start,excluded): break
        time.sleep(.05)
    for item in live_processes(root_pid,root_start,excluded):
        result['kill'].append(signal_verified(item,root_pid,root_start,signal.SIGKILL))
    until=time.monotonic()+1
    while time.monotonic()<until:
        if not live_processes(root_pid,root_start,excluded): break
        time.sleep(.05)
    result['remaining']=live_processes(root_pid,root_start,excluded)
    return result


def trap_cleanup():
    """Only a fresh monitored session may be cleaned; record before signalling."""
    context=json.loads((HOME/'monitor-context.json').read_text())
    session=os.getsid(0); leader=context['leader']; root=context['monitor_pid']; root_start=context['monitor_starttime']
    root_now=proc_identity(root); leader_now=proc_identity(leader)
    if (session!=leader or context['uid']!=2000 or os.getppid()!=leader or not root_now
            or root_now['starttime']!=root_start or not leader_now or leader_now['ppid']!=root
            or leader_now['uid']!=2000 or leader_now['session']!=leader):
        raise RuntimeError('cleanup is not a child of the monitored session leader')
    excluded=(os.getpid(),leader)
    before=live_processes(root,root_start,excluded)
    report={'leader':leader,'before':before,'started':time.monotonic(),'cleanup':None}
    (HOME/'trap-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    report['cleanup']=bounded_session_cleanup(root,root_start,excluded)
    report['finished']=time.monotonic()
    (HOME/'trap-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    # A survivor is a candidate-observation failure even if fixture cleanup succeeds.
    return 1 if before or report['cleanup']['remaining'] else 0


def collect_raw():
    names=('svconfig.json','sv.events','control.events','cleanup-controls.json','notify-control.json',
           'ownership.jsonl','check-error.txt','run.out','run.err','boot.out','boot.err','boot.status',
           'shutdown.out','shutdown.err','status.ready','pid.ready','status.reload','status.stopping',
           'trap-evidence.json','trap.out','trap.err','monitor-context.json')
    records={}
    for name in names:
        try:
            with (HOME/name).open('rb') as f: data=f.read(256*1024+1)
            records[name]={'base64':base64.b64encode(data[:256*1024]).decode(),
                           'truncated':len(data)>256*1024}
        except FileNotFoundError: records[name]={'missing':True}
    return records


def monitor(shell,inner):
    """Subreap the disposable session; preserve all pre-cleanup observations."""
    if shell!='/opt/bashos-parity/candidate' or Path(inner)!=CASE/'case-inner.sh':
        raise RuntimeError('unexpected monitored candidate or script')
    require_subreaper()
    own_identity=proc_identity(os.getpid())
    if not own_identity: raise RuntimeError('cannot observe fixture monitor')
    proc=subprocess.Popen([shell,'--noprofile','--norc',inner],start_new_session=True)
    context={'leader':proc.pid,'uid':os.getuid(),'created':time.monotonic(),
             'monitor_pid':os.getpid(),'monitor_starttime':own_identity['starttime']}
    report={'context':context,'timeout':False,'before_signal':[], 'cleanup':None,
            'emergency_cleanup':None,'reaped':[], 'inner_status':None,'clean':False}
    def interrupted(signo,frame): raise RuntimeError('monitor interrupted by signal %s' % signo)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(sig,interrupted)
    try:
        (HOME/'monitor-context.json').write_text(json.dumps(context)+'\n')
        deadline=time.monotonic()+34
        while proc.poll() is None and time.monotonic()<deadline: time.sleep(.05)
        if proc.poll() is None:
            report['timeout']=True
            report['before_signal']=live_processes(context['monitor_pid'],context['monitor_starttime'])
            (HOME/'monitor-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
            own=proc_identity(proc.pid)
            if own and own['session']==proc.pid and own['uid']==2000:
                report['timeout_signal']=signal_verified(own,context['monitor_pid'],context['monitor_starttime'],signal.SIGTERM)
            grace=time.monotonic()+3
            while proc.poll() is None and time.monotonic()<grace: time.sleep(.05)
        if proc.poll() is None:
            own=proc_identity(proc.pid)
            if own and own['session']==proc.pid and own['uid']==2000:
                report['timeout_kill']=signal_verified(own,context['monitor_pid'],context['monitor_starttime'],signal.SIGKILL)
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: report['inner_still_alive']=True
        report['inner_status']=proc.poll()
        report['cleanup']=bounded_session_cleanup(context['monitor_pid'],context['monitor_starttime'])
        try: trap=json.loads((HOME/'trap-evidence.json').read_text())
        except (OSError,ValueError): trap={'missing_or_invalid':True}
        report['trap']=trap
        report['clean']=(not report['timeout'] and report['inner_status']==0
               and not report['cleanup']['before'] and not report['cleanup']['remaining']
               and not trap.get('missing_or_invalid') and not trap.get('before')
               and not (trap.get('cleanup') or {}).get('remaining'))
    except BaseException as exc:
        report['exception']=repr(exc); report['clean']=False
    finally:
        # An interrupt or an internal fixture error must not skip bounded cleanup.
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(sig,signal.SIG_IGN)
        try:
            still=live_processes(context['monitor_pid'],context['monitor_starttime'])
            if still:
                report['emergency_before']=still
                (HOME/'monitor-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
                report['emergency_cleanup']=bounded_session_cleanup(context['monitor_pid'],context['monitor_starttime'])
                report['clean']=False
            try: proc.wait(timeout=1)
            except subprocess.TimeoutExpired: report['inner_still_alive']=True; report['clean']=False
            # waitpid(-1) only reaps direct children adopted by this subreaper;
            # the exact PID and raw wait status are retained for each one.
            until=time.monotonic()+2
            while time.monotonic()<until:
                try: pid,status=os.waitpid(-1,os.WNOHANG)
                except ChildProcessError: break
                if pid>0: report['reaped'].append({'pid':pid,'status':status})
                else: time.sleep(.05)
            report['remaining_final']=live_processes(context['monitor_pid'],context['monitor_starttime'])
            if report['remaining_final']: report['clean']=False
        except BaseException as exc:
            report['cleanup_exception']=repr(exc); report['clean']=False
        report['raw']=collect_raw()
        (HOME/'monitor-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    print('monitor-clean='+('ok' if report.get('clean') else 'BAD'))
    return 0 if report.get('clean') else 1


def cleanup_controls(scenario):
    """Control forced reaping and the orphan/subreaper path independently."""
    require_subreaper()
    if scenario not in ('run','notify'): raise ValueError('unexpected control scenario')
    root=proc_identity(os.getpid()); root_pid=os.getpid(); root_start=root['starttime']
    name='life' if scenario=='run' else 'a_notify'
    runpath=HOME/'services'/name/'run'; controls=[]
    for mode in ('parent-only-term','parent-sigkill'):
        outpath=HOME/('control-'+mode+'.out'); errpath=HOME/('control-'+mode+'.err')
        with outpath.open('wb') as out, errpath.open('wb') as err:
            proc=subprocess.Popen([str(runpath)],stdout=out,stderr=err,start_new_session=True)
            child_pid=None; child_birth=None; reaped=None; killed_fallback=False; failure=''
            try:
                until=time.monotonic()+4
                while time.monotonic()<until:
                    children=[x for x in read_events() if x.get('name')==name and x.get('kind')=='child-start']
                    if children and (HOME/('started.'+name)).exists():
                        child_pid=children[-1]['pid']; child_birth=children[-1]['proc_starttime']; break
                    time.sleep(.025)
                if child_pid is None: raise RuntimeError('control child not ready')
                parent=proc_identity(proc.pid)
                if not parent or parent['session']!=proc.pid or parent['uid']!=2000:
                    raise RuntimeError('control parent identity mismatch')
                signo=signal.SIGTERM if mode=='parent-only-term' else signal.SIGKILL
                signal_verified(parent,root_pid,root_start,signo)
                proc.wait(timeout=6)
                if mode=='parent-sigkill':
                    until=time.monotonic()+4
                    while time.monotonic()<until:
                        try: pid,status=os.waitpid(child_pid,os.WNOHANG)
                        except ChildProcessError: pid=0
                        if pid==child_pid: reaped={'pid':pid,'status':status}; break
                        time.sleep(.025)
                    ev=read_events()
                    watchdog=[x for x in ev if x.get('pid')==child_pid and x.get('kind') in ('child-signal','child-parent-gone')]
                    if (proc.returncode!=-signal.SIGKILL or reaped is None or reaped['pid']!=child_pid or not watchdog):
                        raise RuntimeError('orphan watchdog or exact subreaper reap failed')
                else:
                    ev=read_events()
                    forced=[x for x in ev if x.get('kind')=='child-forced-cleanup']
                    got=[x for x in ev if x.get('kind')=='child-reaped']
                    pre=[x for x in ev if x.get('kind')=='child-cleanup-pre']
                    observed=pre[0].get('observation') if len(pre)==1 else None
                    if (proc.returncode!=0 or len(forced)!=1 or forced[0].get('child')!=child_pid
                            or len(got)!=1 or got[0].get('child')!=child_pid or not got[0].get('forced')
                            or not os.WIFSIGNALED(got[0].get('status',0)) or os.WTERMSIG(got[0]['status'])!=signal.SIGKILL
                            or not observed or observed.get('pid')!=child_pid or observed.get('starttime')!=child_birth
                            or observed.get('ppid')!=proc.pid or observed.get('state')=='Z' or normal_child_cleanup(ev,name)):
                        raise RuntimeError('forced cleanup control did not prove failure and exact reap')
            except BaseException as exc:
                failure=repr(exc)
            finally:
                # Clean only identities in this freshly created control session.
                fallback=bounded_session_cleanup(root_pid,root_start)
                killed_fallback=bool(fallback['before'])
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: failure += ' parent-still-live'
                if child_pid is not None and reaped is None:
                    try:
                        pid,status=os.waitpid(child_pid,os.WNOHANG)
                        if pid==child_pid: reaped={'pid':pid,'status':status}
                    except ChildProcessError: pass
                controls.append({'mode':mode,'parent':proc.pid,'parent_status':proc.returncode,
                                 'child':child_pid,'child_starttime':child_birth,'reaped_by_subreaper':reaped,
                                 'events_raw':EVENTS.read_text() if EVENTS.exists() else '',
                                 'stdout_base64':base64.b64encode(outpath.read_bytes()).decode(),
                                 'stderr_base64':base64.b64encode(errpath.read_bytes()).decode(),
                                 'fallback':fallback,'fallback_needed':killed_fallback,'failure':failure})
                EVENTS.write_text('')
                for filename in ('child-ready','started.'+name):
                    try: (HOME/filename).unlink()
                    except FileNotFoundError: pass
            if failure or killed_fallback:
                (HOME/'cleanup-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
                raise RuntimeError('cleanup control failed: '+failure)
    (HOME/'cleanup-controls.json').write_text(json.dumps(controls,indent=2)+'\n')

def check(scenario):
    e=read_events(); kinds=lambda name:[x['kind'] for x in e if x['name']==name]
    ok=False
    if scenario=='once':
        ok=kinds('once')==['start','exit','finish'] and [x for x in e if x['kind']=='finish'][0].get('args')==['7']
    elif scenario=='oneshot':
        ok=kinds('onceup')==['start','exit','finish'] and (HOME/'state/onceup/status').read_text().strip()=='oneshot-ok'
    elif scenario=='restart':
        ok=True
        for name,count in [('always',3),('failure',3),('success',1),('never',1)]:
            starts=[x for x in e if x['name']==name and x['kind']=='start']
            ok &= len(starts)==count
            if count==3: ok &= all(starts[i+1]['time']-starts[i]['time']>=.8 for i in range(2))
            state=(HOME/'state'/name/'status').read_text().strip()
            ok &= state.startswith('restart-limit') if count==3 else state.startswith('exited rc=')
    elif scenario=='order':
        names=['zbase','mbefore','ayrequires','bafter']
        starts=[x['name'] for x in e if x['kind']=='start']
        finish=[x['name'] for x in e if x['kind']=='finish']
        ok=starts==names and finish==names[::-1]
        for n in names: ok &= 'probe-ok' in kinds(n)
    elif scenario=='life':
        life=[x for x in e if x['name']=='life']
        starts=[x for x in life if x['kind']=='start']; finishes=[x for x in life if x['kind']=='finish']; signals=[x for x in life if x['kind']=='signal']
        try: text=(HOME/'status.out').read_text(); alltext=(HOME/'status-all.out').read_text()
        except OSError:text=''; alltext=''
        witness=[x for x in e if x['name']=='witness' and x['kind']=='signal']
        ok=(len(starts)==2 and len(finishes)==2 and starts[0]['pid']!=starts[1]['pid']
            and not any(x.get('number')==signal.SIGUSR1 for x in witness)
            and any(x['number']==signal.SIGUSR1 and x['pid']==starts[0]['pid'] for x in signals)
            and f"running pid={starts[0]['pid']}" in text and f"running pid={starts[0]['pid']}" in alltext
            and all(any(x['kind']=='exit' and x['pid']==p['pid'] and x['time']<f['time'] for x in life) for p,f in zip(starts,finishes)))
    elif scenario=='run':
        life=[x for x in e if x['name']=='life']; starts=[x for x in life if x['kind']=='start']; ends=[x for x in life if x['kind']=='finish']
        children=[x for x in life if x['kind']=='child-start']; reaped=[x for x in life if x['kind']=='child-reaped']; signals=[x for x in life if x['kind']=='child-signal']
        ok=(normal_child_cleanup(e,'life') and len(starts)==len(ends)==1
            and any(x['kind']=='exit' and x['pid']==starts[0]['pid'] and not x.get('expired') and x['time']<ends[0]['time'] for x in life))
    elif scenario=='window':
        starts=[x for x in e if x['name']=='window' and x['kind']=='start']
        ok=len(starts)==3 and starts[1]['time']-starts[0]['time']>=1.8 and starts[2]['time']-starts[1]['time']>=1.8
    elif scenario in ('timeout','command','probe'):
        first='a_probe' if scenario in ('timeout','probe') else 'a_command'
        if scenario=='timeout':
            try: state=(HOME/'timeout-status').read_text()
            except OSError: state=''
            ok='readiness-failed timeout' in state and 'start' not in kinds('z_dependent') and 'probe-start' in kinds(first)
        else:
            p=[x for x in e if x['name']==first and x['kind']=='probe-ok']; d=[x for x in e if x['name']=='z_dependent' and x['kind']=='start']
            ok=len(p)==len(d)==1 and p[0]['time']<d[0]['time']
    elif scenario=='notify':
        texts=[]
        for t in ('ready','reload','stopping'):
            try:texts.append((HOME/('status.'+t)).read_text())
            except OSError:texts.append('')
        starts=[x for x in e if x['name']=='a_notify' and x['kind']=='start']; messages=[x for x in e if x['name']=='a_notify' and x['kind']=='notify']; depend=[x for x in e if x['name']=='z_dependent' and x['kind']=='start']
        children=[x for x in e if x['name']=='a_notify' and x['kind']=='child-start']
        ok=normal_child_cleanup(e,'a_notify') and len(starts)==1 and len(children)==1 and children[0]['ppid']==starts[0]['pid'] and len(messages)==3 and len(depend)==1
        if ok:
            pid=children[0]['pid']; expected=[f'READY=1\nSTATUS=fixture-ready\nMAINPID={pid}'.encode(),b'RELOADING=1\nSTATUS=fixture-reloading',b'STOPPING=1\nSTATUS=fixture-stopping']
            ok &= [bytes.fromhex(x['wire_hex']) for x in messages]==expected and all(x['target']=='@sv/a_notify' for x in messages)
            ok &= f'ready pid={pid} status=fixture-ready' in texts[0] and f'reloading pid={pid} status=fixture-reloading' in texts[1] and f'stopping pid={pid} status=fixture-stopping' in texts[2]
            try: observed_pid=int((HOME/'pid.ready').read_text())
            except (OSError,ValueError): observed_pid=-1
            ok &= observed_pid==pid and messages[0]['time']<depend[0]['time']
    elif scenario=='socket':
        x=[x for x in e if x['name']=='socket' and x['kind']=='socket']; starts=[x for x in e if x['name']=='socket' and x['kind']=='start']
        ok=len(x)==len(starts)==1 and x[0].get('listen_fds')=='1' and x[0].get('listen_pid')==str(starts[0]['pid']) and x[0].get('listen_fdnames')=='socket' and x[0].get('accepting')==1 and x[0].get('request_hex')==b'ping'.hex()
    elif scenario=='path': ok=len([x for x in e if x['name']=='path' and x['kind']=='start'])==6
    print(scenario+'-observation='+('ok' if ok else 'BAD'))


if __name__=='__main__':
    guard()
    entry=Path(sys.argv[0]).name
    if entry in ('run','finish','check'):
        name=Path(sys.argv[0]).parent.name; config=json.loads((HOME/'svconfig.json').read_text())[name]
        if entry=='run':raise SystemExit(run(name,config))
        if entry=='finish':event(name,'finish',args=sys.argv[1:]);raise SystemExit(0)
        raise SystemExit(probe(name))
    if len(sys.argv)==3 and sys.argv[1]=='--setup': setup(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=='--check':
        try: check(sys.argv[2])
        except (OSError,ValueError,KeyError,IndexError) as exc:
            (HOME/'check-error.txt').write_text(repr(exc)+'\n'); print(sys.argv[2]+'-observation=BAD')
    elif len(sys.argv) in (2,3) and sys.argv[1]=='--safe-tree': raise SystemExit(safe_tree(sys.argv[2] if len(sys.argv)==3 else None))
    elif len(sys.argv)==3 and sys.argv[1]=='--cleanup-controls': cleanup_controls(sys.argv[2])
    elif sys.argv[1:]==['--trap-cleanup']: raise SystemExit(trap_cleanup())
    elif len(sys.argv)==4 and sys.argv[1]=='--monitor': raise SystemExit(monitor(sys.argv[2],sys.argv[3]))
    elif sys.argv[1:]==['--stop-witness']:
        events=[e for e in read_events() if e.get('name')=='witness' and e.get('kind')=='start']
        if events:
            e=events[-1]; pid=e['pid']; proc=Path('/proc')/str(pid)
            try:
                fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
                if fields[0]!='Z' and proc.stat().st_uid==2000 and int(fields[19])==e['proc_starttime'] and str(HOME/'sv-helper').encode() in (proc/'cmdline').read_bytes():
                    os.kill(pid,signal.SIGTERM)
            except (OSError,ValueError,IndexError): pass
    elif sys.argv[1:]==['--witness']: raise SystemExit(run('witness',{'kind':'long'}))
    elif len(sys.argv)==3 and sys.argv[1]=='--probe': raise SystemExit(probe(sys.argv[2]))
    elif sys.argv[1:]==['--path-control']:
        libc=ctypes.CDLL(None,use_errno=True)
        masks={'create':0x100,'modify':0x2,'delete':0x200,'move':0xc0,'close-write':0x8,'0x100':0x100}
        records=[]
        for name,mask in masks.items():
            folder=HOME/('control-watch-'+name); folder.mkdir(); item=folder/'item'; item.write_bytes(b'old')
            fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            if fd<0 or libc.inotify_add_watch(fd,os.fsencode(folder),mask)<0: raise SystemExit('CONTROL-FAILED inotify setup')
            if name in ('create','0x100'): (folder/'new').write_bytes(b'x')
            elif name in ('modify','close-write'):
                with item.open('ab') as f: f.write(b'x')
            elif name=='delete': item.unlink()
            else: item.rename(folder/'moved')
            if not select.select([fd],[],[],2)[0]: raise SystemExit('CONTROL-FAILED inotify event')
            raw=os.read(fd,4096); os.close(fd)
            wd,flags,cookie,length=struct.unpack_from('iIII',raw)
            if not flags & mask: raise SystemExit('CONTROL-FAILED inotify mask')
            records.append({'operation':name,'requested_mask':mask,'observed_mask':flags,'raw_hex':raw.hex()})
        (HOME/'path-control.json').write_text(json.dumps(records,indent=2)+'\n')
    elif sys.argv[1:]==['--notify-control']:
        address='\0fixture-control-'+str(os.getpid()); receiver=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); receiver.bind(address); receiver.settimeout(2)
        sender=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); wire=b'READY=1\nSTATUS=fixture-ready'; sender.sendto(wire,address); got=receiver.recv(1024)
        sender.close(); receiver.close()
        if got!=wire: raise SystemExit('CONTROL-FAILED notify datagram')
        (HOME/'notify-control.json').write_text(json.dumps({'wire_hex':wire.hex(),'received_hex':got.hex()})+'\n')
    elif len(sys.argv)==3 and sys.argv[1]=='--connect':
        s=socket.create_connection(('127.0.0.1',int(sys.argv[2])),timeout=3); s.sendall(b'ping'); got=s.recv(128); s.close(); (HOME/'socket-peer.bin').write_bytes(got); print('peer='+('ok' if got==b'pong' else 'BAD'))
    else: raise SystemExit('unexpected invocation')
