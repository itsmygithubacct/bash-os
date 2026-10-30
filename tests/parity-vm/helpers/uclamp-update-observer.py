#!/usr/bin/python3
"""Guest-only owned-child clamp updates with separate util-linux controls."""
import ctypes,json,os,select,subprocess,sys,time,uuid
from pathlib import Path
H=Path('/tmp/parity-home');C=Path('/tmp/parity-case');TASK='/opt/bashos-parity/harness/helpers/uclamp-selfread-task.py'
if os.getuid()!=2000 or os.geteuid()!=2000 or Path.cwd()!=C or os.environ.get('HOME')!=str(H):raise SystemExit(125)
if Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.uname().release!='7.2.11+deb13-amd64':raise SystemExit(125)
uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
class Attr(ctypes.Structure):
 _fields_=[('size',ctypes.c_uint32),('policy',ctypes.c_uint32),('flags',ctypes.c_uint64),('nice',ctypes.c_int32),('priority',ctypes.c_uint32),('runtime',ctypes.c_uint64),('deadline',ctypes.c_uint64),('period',ctypes.c_uint64),('util_min',ctypes.c_uint32),('util_max',ctypes.c_uint32)]
lib=ctypes.CDLL(None,use_errno=True);lib.syscall.restype=ctypes.c_long
def external_get(pid):
 a=Attr();a.size=ctypes.sizeof(a)
 if lib.syscall(315,pid,ctypes.byref(a),ctypes.sizeof(a),0):raise OSError(ctypes.get_errno(),'sched_getattr pid')
 return {n:getattr(a,n) for n,_ in Attr._fields_}
def identity(pid):
 s=Path('/proc/%d/stat'%pid).read_text();at=s.rfind(')');f=s[at+1:].split()
 if at<0 or len(f)<20 or f[0] in ('Z','X','x'):raise RuntimeError('dead or invalid owned child')
 return {'pid':pid,'ppid':int(f[1]),'uid':os.stat('/proc/%d'%pid).st_uid,'start_ticks':int(f[19])}
def line(stream):
 end=time.monotonic()+10;b=bytearray()
 while len(b)<8192:
  wait=end-time.monotonic()
  if wait<=0 or not select.select([stream],[],[],wait)[0]:raise RuntimeError('owned child timeout')
  x=os.read(stream.fileno(),1)
  if not x:raise RuntimeError('owned child closed pipe')
  if x==b'\n':return json.loads(bytes(b))
  b+=x
 raise RuntimeError('owned child line too long')
def run(argv):
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 return {'argv':argv,'status':p.returncode,'stdout':p.stdout.decode('utf8','backslashreplace'),'stderr':p.stderr.decode('utf8','backslashreplace')}
def live(p,fd,birth):
 poll=select.poll();poll.register(fd,select.POLLIN)
 if p.poll() is not None or poll.poll(0) or identity(p.pid)!=birth:raise RuntimeError('owned child identity or pidfd changed')
 return {'identity':birth,'pidfd_alive':True}
def self_read(p,fd,birth):
 live(p,fd,birth);p.stdin.write(b'read\n');p.stdin.flush();x=line(p.stdout);live(p,fd,birth)
 if (x.get('pid'),x.get('ppid'),x.get('uid'))!=(p.pid,os.getpid(),2000):raise RuntimeError('self-read identity differs')
 x['independent_attr']=external_get(p.pid)
 if x.get('attr')!=x['independent_attr']:raise RuntimeError('self and independent read disagree')
 return x
def save(r):(H/'setter-update-report.json').write_text(json.dumps(r,sort_keys=True)+'\n')
def execute(shell,kind,opts,expected,report):
 p=subprocess.Popen(['/usr/bin/python3','-I',TASK],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0);fd=None;item={'kind':kind,'opts':opts};report['runs'].append(item);save(report)
 try:
  ready=line(p.stdout);birth=identity(p.pid)
  if (ready.get('pid'),ready.get('ppid'),ready.get('uid'))!=(p.pid,os.getpid(),2000) or birth['ppid']!=os.getpid() or birth['uid']!=2000 or birth['start_ticks']<=0:raise RuntimeError('owned child creation binding failed')
  fd=os.pidfd_open(p.pid,0);item['birth']=live(p,fd,birth)
  live(p,fd,birth);seed=run(['/usr/bin/uclampset','-m','200','-M','800','-p',str(p.pid)]);item['seed']=seed
  if seed['status']!=0:raise RuntimeError('native seed failed')
  before=self_read(p,fd,birth);item['before']=before
  if (before['attr']['util_min'],before['attr']['util_max'])!=(200,800):raise RuntimeError('seed readback differs')
  item['precall_live']=live(p,fd,birth);save(report)
  argv=(['/usr/bin/uclampset',*opts,'-p',str(p.pid)] if kind=='native' else [shell,'--noprofile','--norc','-c','uclampset "$@"','owned-update',*opts,'-p',str(p.pid)])
  item['operation']=run(argv);save(report)
  item['after']=self_read(p,fd,birth);item['after_live']=live(p,fd,birth);save(report)
  attr=item['after']['attr'];other=('policy','nice','priority','runtime','deadline','period')
  item['checks']={'status':item['operation']['status']==0,'stderr_empty':item['operation']['stderr']=='','expected_pair':(attr['util_min'],attr['util_max'])==expected,'other_attrs_preserved':all(attr[k]==before['attr'][k] for k in other)};save(report)
  return item
 finally:
  forced=False;cleanup_error=None
  try:
   if p.poll() is None:
    try:p.stdin.write(b'exit\n');p.stdin.flush();p.wait(timeout=5)
    except (OSError,subprocess.TimeoutExpired):forced=True;p.kill();p.wait(timeout=5)
   item['cleanup']={'returncode':p.returncode,'forced':forced,'reaped':p.returncode is not None}
  except (OSError,subprocess.TimeoutExpired) as e:
   cleanup_error=type(e).__name__+': '+str(e);item['cleanup']={'returncode':p.poll(),'forced':forced,'reaped':False,'error':cleanup_error}
  finally:
   if fd is not None:os.close(fd)
   save(report)
  if cleanup_error or forced or p.returncode!=0:raise RuntimeError('owned child cleanup incomplete')
def main():
 shell=sys.argv[1];r={'runs':[],'control_valid':False,'candidate_checks':{}};specs=[('min',['-m','300'],(300,800)),('max',['-M','700'],(200,700)),('pair',['-m','350','-M','650'],(350,650))]
 try:
  for name,opts,expected in specs:
   native=execute(shell,'native',opts,expected,r)
   if not all(native['checks'].values()):raise RuntimeError('native '+name+' control failed')
  r['control_valid']=True;save(r)
  for name,opts,expected in specs:
   cand=execute(shell,'candidate',opts,expected,r);native=r['runs'][len(r['candidate_checks'])]
   checks=dict(cand['checks']);checks['matches_native']=(cand['after']['attr']['util_min'],cand['after']['attr']['util_max'])==(native['after']['attr']['util_min'],native['after']['attr']['util_max'])
   r['candidate_checks'][name]=checks;save(r)
  if not all(all(v.values()) for v in r['candidate_checks'].values()):raise SystemExit(1)
  print('owned child setter updates ok')
 except (OSError,RuntimeError,ValueError,KeyError,TypeError,AttributeError,subprocess.TimeoutExpired) as e:r['incomplete']=type(e).__name__+': '+str(e);save(r);raise SystemExit(125)
if __name__=='__main__':main()
