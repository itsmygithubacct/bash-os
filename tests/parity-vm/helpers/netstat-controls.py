#!/usr/bin/python3
"""Disposable-VM-only same-UID netstat transport controls and fixtures."""
import errno, json, os, re, socket, struct, subprocess, sys, uuid, signal
from pathlib import Path
HOME=Path('/tmp/parity-home'); OBS='/opt/bashos-parity/harness/helpers/netstat-observer.py'
TABLES=('tcp','tcp6','udp','udp6','unix')
def save(name, obj):
    tmp=HOME/(name+'.tmp'); tmp.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n'); os.replace(tmp,HOME/name)
def guard():
    assert os.getuid()==os.geteuid()==2000 and Path.cwd()==Path('/tmp/parity-case') and os.environ.get('HOME')==str(HOME)
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    assert Path('/sys/class/dmi/id/sys_vendor').read_text().strip()=='QEMU'
    assert subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip() in ('qemu','kvm')
def probe(denied):
    results={}
    try: socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4).close(); results['diag_errno']=0
    except OSError as e: results['diag_errno']=e.errno
    for n in TABLES:
        try:
            with open('/proc/net/'+n,'rb') as f: f.read(1)
            results[n]=0
        except OSError as e: results[n]=e.errno
    with open('/etc/bashos-parity-vm','rb') as f: assert f.read(1)
    save('probe.json',results)
    assert results['diag_errno']==errno.EPERM and all(results[n]==(errno.EACCES if denied else 0) for n in TABLES)
def events(name):
    out=[]
    for line in (HOME/name).read_text().splitlines():
        row=json.loads(line); assert row['response_status']=='sent' and not row.get('path_unreadable')
        req=bytes.fromhex(row['request_hex']); resp=bytes.fromhex(row['response_hex']); assert len(req)==80 and len(resp)==24
        ident,pid,flags,nr,arch,ip=struct.unpack_from('<QIIiIQ',req); args=list(struct.unpack_from('<6Q',req,32)); rid,value,error,rflags=struct.unpack('<QqiI',resp)
        assert (ident,pid,nr,arch,ip,args)==(row['id'],row['pid'],row['syscall_number'],row['arch'],row['instruction_pointer'],row['args']) and rid==ident
        assert (row['reply']=='continue' and error==0 and rflags==1) or (row['reply'].startswith('errno:') and error==-int(row['reply'].split(':')[1]) and rflags==0)
        out.append(row)
    return out
def invoke(mode, argv):
    log=HOME/(mode+'-events.jsonl'); log.write_text('')
    cmd=['/usr/bin/python3',OBS,'--notify','socket:0=16,2=4','--reply','socket=EPERM','--notify','openat','--log-string','openat=1','--log',str(log),'--']+argv
    env=dict(os.environ,BASHOS_NETSTAT_DENY_PROC='1' if mode in ('control-denied','denied') else '0')
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
    try:
        stdout,stderr=p.communicate(timeout=25)
        (HOME/(mode+'.out')).write_bytes(stdout); (HOME/(mode+'.err')).write_bytes(stderr)
        save(mode+'-status.json',{'returncode':p.returncode,'timeout':False})
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL); stdout,stderr=p.communicate()
        (HOME/(mode+'.out')).write_bytes(stdout); (HOME/(mode+'.err')).write_bytes(stderr)
        save(mode+'-status.json',{'returncode':None,'timeout':True}); raise RuntimeError('observer timeout: incomplete')
    return p,stdout,stderr,events(mode+'-events.jsonl')
def check_trace(rows, denied, expected_pid=None):
    if expected_pid is not None: rows=[r for r in rows if r['pid']==expected_pid]
    sock=[r for r in rows if r['syscall']=='socket' and r['args'][0]==socket.AF_NETLINK and r['args'][2]==4 and r['reply']=='errno:1']
    assert len({r['pid'] for r in sock})==1, 'ambiguous diag caller'
    owner=sock[0]['pid']
    table={n:[r for r in rows if r['pid']==owner if r['syscall']=='openat' and r.get('string1')=='/proc/net/'+n and r['reply']==('errno:13' if denied else 'continue')] for n in TABLES}
    assert sock and all(table.values()), 'missing observed candidate socket/path denial/fallback'
    return {'diag_events':len(sock),'tables':{k:len(v) for k,v in table.items()},'pid':expected_pid}
def control(denied):
    mode='control-denied' if denied else 'control-fallback'
    p,stdout,stderr,rows=invoke(mode,['/usr/bin/python3',__file__,'probe-denied' if denied else 'probe-fallback'])
    assert p.returncode==0; trace=check_trace(rows,denied); save(mode+'-verified.json',trace)
def fixture():
    holders=[]; info={}
    for n,fam,typ,addr in [('tcp',socket.AF_INET,socket.SOCK_STREAM,('127.0.0.1',0)),('tcp6',socket.AF_INET6,socket.SOCK_STREAM,('::1',0)),('udp',socket.AF_INET,socket.SOCK_DGRAM,('127.0.0.1',0)),('udp6',socket.AF_INET6,socket.SOCK_DGRAM,('::1',0))]:
        s=socket.socket(fam,typ); s.bind(addr)
        if typ==socket.SOCK_STREAM: s.listen(1)
        holders.append(s); info[n]={'port':s.getsockname()[1],'inode':int(os.readlink('/proc/self/fd/'+str(s.fileno())).split('[')[1][:-1])}
    path=str(HOME/'netstat-owned.sock'); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(path); s.listen(1); holders.append(s)
    info['unix']={'path':path,'inode':int(os.readlink('/proc/self/fd/'+str(s.fileno())).split('[')[1][:-1])}
    for n in TABLES:
        data=Path('/proc/net/'+n).read_text(); assert len(data)<512*1024; (HOME/('proc-'+n+'.txt')).write_text(data)
        lines=[x for x in data.splitlines() if re.search(r'(?<!\d)'+str(info[n]['inode'])+r'(?!\d)',x)]
        assert len(lines)==1, 'fixture inode not unique in proc '+n
        info[n]['proc_line']=lines[0]
    save('fixture.json',info); return holders,info
def run_candidate(mode,bash):
    holders,info=fixture()
    try:
        target=HOME/'target-pid'; target.unlink(missing_ok=True)
        shell='printf "%s\\n" "$$" > "$HOME/target-pid" || exit 125; netstat -tux 2>"$HOME/candidate.err"'
        p,stdout,stderr,rows=invoke(mode,[bash,'--noprofile','--norc','-c',shell]); pid=int(target.read_text()); trace=check_trace(rows,mode=='denied',pid);save(mode+'-trace.json',trace)
        text=stdout.decode('utf-8','replace'); lines=text.splitlines(); observations={}
        for n in ('tcp','tcp6','udp','udp6'):
            item=info[n]; expected_addr=('127.0.0.1:' if n in ('tcp','udp') else '::1:')+str(item['port']); matches=[x for x in lines if x.split() and x.split()[0]==n and expected_addr in x.split()]
            observations[n]={'address':expected_addr,'rows':matches,'proc_line':item['proc_line']}
        matches=[x for x in lines if info['unix']['path'] in x.split()];observations['unix']={'path':info['unix']['path'],'rows':matches,'proc_line':info['unix']['proc_line']}
        save(mode+'-observations.json',observations)
        if mode=='fallback':
            assert p.returncode==0 and all(len(observations[n]['rows'])==1 for n in TABLES), 'missing, duplicate, or failed owned fallback rows'
            for n in ('tcp','tcp6','udp','udp6'):
                fields=observations[n]['rows'][0].split()
                assert len(fields)>=6 and fields[1:3]==['0','0']
                assert fields[4]==('0.0.0.0:*' if n in ('tcp','udp') else ':::*')
            for n in ('tcp','tcp6'): assert observations[n]['rows'][0].split()[-1]=='LISTEN'
            for n in ('udp','udp6'): assert observations[n]['rows'][0].split()[-1]=='UNCONN'
            # Legacy Unix LISTENING spelling is an original documented expectation.
            assert observations['unix']['rows'][0].split()[-1]=='LISTENING'
        else:
            assert p.returncode!=0 and bool((HOME/'candidate.err').read_bytes().strip()), 'denied transport needs failure and diagnostic'
        print(mode+'=verified')
    finally:
        for s in holders: s.close()
        (HOME/'netstat-owned.sock').unlink(missing_ok=True)
if __name__=='__main__':
    guard();mode=sys.argv[1]
    if mode.startswith('probe-'): probe(mode=='probe-denied')
    elif mode.startswith('control-'): control(mode=='control-denied')
    elif mode in ('fallback','denied'): run_candidate(mode,sys.argv[2])
    else: raise ValueError('invalid mode')
