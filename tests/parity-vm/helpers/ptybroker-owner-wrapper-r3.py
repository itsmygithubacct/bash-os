#!/usr/bin/python3
"""Guest-only UID-2000 supervisor of the root-mapped owner observer."""
import json,os,signal,stat,subprocess,sys,tempfile,time,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case');INNER='/opt/bashos-parity/harness/helpers/ptybroker-owner-r3.py'
class Incomplete(Exception):pass

def save(path,obj):
    tmp=path.with_name(path.name+'.tmp');data=(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(data)>32768:raise Incomplete('outer proof exceeds cap')
    fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)

def proc(pid):
    p=Path('/proc')/str(pid);s=(p/'stat').read_text();fields=s.rsplit(')',1)[1].split();status=(p/'status').read_text();uid=next(x.split()[1:5] for x in status.splitlines() if x.startswith('Uid:')); exe=os.stat(p/'exe')
    return {'pid':pid,'ppid':int(fields[1]),'pgrp':int(fields[2]),'session':int(fields[3]),'starttime':int(fields[19]),'uid':[int(x) for x in uid],'exe_dev':exe.st_dev,'exe_ino':exe.st_ino,'stat_raw':s,'status_raw':status}

def main():
    if len(sys.argv)!=2 or os.getuid()!=2000 or os.geteuid()!=2000 or os.getgid()!=2000 or Path.cwd()!=C or os.environ.get('HOME')!=str(H):raise Incomplete('outer uid/path mismatch')
    token=str(uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip()))
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU':raise Incomplete('not QEMU')
    candidate=sys.argv[1]; done=set();limit=time.monotonic()+55
    with tempfile.TemporaryFile(dir=H) as out,tempfile.TemporaryFile(dir=H) as err:
        p=subprocess.Popen(['/usr/bin/unshare','--user','--map-root-user','--fork','/usr/bin/python3','-I',INNER,candidate],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
        try:
            while p.poll() is None:
                if time.monotonic()>limit:raise Incomplete('mapped observer timeout')
                for tag in ('owner-native','owner-control','owner-candidate'):
                    request=H/(tag+'-identity.json');ack=H/(tag+'-outer-uid.json')
                    if tag in done or not request.is_file():continue
                    data=json.loads(request.read_text());pid=data['pid'];outside=proc(pid)
                    if outside['uid']!=[2000]*4 or outside['ppid']!=data['ppid'] or outside['pgrp']!=data['pgrp'] or outside['session']!=data['session'] or outside['starttime']!=data['starttime'] or (outside['exe_dev'],outside['exe_ino'])!=(data['exe_dev'],data['exe_ino']):raise Incomplete('outer identity mismatch')
                    ancestry=[];cursor=outside['ppid']
                    for _ in range(8):
                        row=proc(cursor);ancestry.append(row)
                        if cursor==p.pid:break
                        cursor=row['ppid']
                    if not ancestry or ancestry[-1]['pid']!=p.pid or any(row['uid']!=[2000]*4 for row in ancestry):raise Incomplete('not a wrapper-owned process tree')
                    save(ack,{'token':token,'identity':data,'outer_uid':outside['uid'],'namespace_uid':data['namespace_uid'],'outer_proc':outside,'wrapper':proc(os.getpid()),'unshare_pid':p.pid,'ancestry':ancestry,'ancestry_proven':True})
                    done.add(tag)
                time.sleep(.01)
            status=p.returncode
            out.seek(0);err.seek(0);o=out.read(1024*1024+1);e=err.read(1024*1024+1)
            if len(o)>1024*1024 or len(e)>1024*1024:raise Incomplete('wrapper output truncated')
            os.write(1,o);os.write(2,e)
            return status
        finally:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGKILL)
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:pass
if __name__=='__main__':
    try:status=main()
    except BaseException as exc:print('OWNER-OUTER-INCOMPLETE: '+repr(exc),file=sys.stderr);sys.exit(125)
    else:sys.exit(status)
