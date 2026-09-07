#!/usr/bin/env python3
"""Check selection contracts before any compiler or download is needed."""
from pathlib import Path
import json
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parent.parent
checks=0

def run(*args, ok=True, env=None):
    global checks
    p=subprocess.run(['./build.sh',*args],cwd=ROOT,env=env,capture_output=True,text=True)
    assert (p.returncode==0)==ok,(args,p.returncode,p.stdout,p.stderr)
    checks+=1
    return p

def plan(*args, **kwargs):
    return json.loads(run(*args,'--show-config',**kwargs).stdout)

profiles=['shell','pure','core','device','server','desktop','full']
p={name:plan('--profile',name) for name in profiles}
assert not p['shell']['names']
assert len(p['pure']['names'])==28
for smaller,larger in [('shell','pure'),('pure','core'),('core','device'),('device','server'),('core','desktop'),('server','full'),('desktop','full')]:
    assert set(p[smaller]['names']) < set(p[larger]['names'])
assert {'ls','grep','find','sort','cut','seq'} <= set(p['core']['names'])
assert {'ip','bashmount','procstat'} <= set(p['device']['names'])
assert {'ssh','sshd','crypto','sqlite'} <= set(p['server']['names'])
assert {'nano','ts','hl','tiv'} <= set(p['desktop']['names'])
assert not p['core']['libraries'] and not p['device']['libraries']
for level,name in enumerate(['shell','pure','core','device','server','full']):
    assert plan('--level',str(level))['names']==p[name]['names']
assert plan()['names']==p['full']['names']
assert plan('--profile=core')['names']==p['core']['names']
assert plan('--include','cut,seq','--include','cut')['names']==['cut','seq']
assert plan('--profile','core','--include','nano,ts')['names'][-2:]==['nano','ts']
assert 'ed' not in plan('--profile','core','--exclude','ed')['names']
assert plan('--include','cut','--exclude','cut')['names']==[]
assert plan('--include','cut')['tag'] != plan('--include','seq')['tag']
assert plan('--profile','device','--name','appliance')['tag']=='appliance'
for args in [('--profile','missing'),('--level','6'),('--profile','core','--level','2'),
             ('--profile','core','--list','config/bash-loadables.list'),('--include','typo'),
             ('--include','nano'),('--include','doas'),('--profile','desktop','--exclude','ts'),
             ('--exclude','typo'),('--include','cut;id'),('--name','../../outside'),
             ('--profile',),('--include-list','/nonexistent/inclusion-list')]:
    run(*args,'--show-config',ok=False)
for name, companion in [('killall','pgrep'),('pkill','pgrep'),('netstat','ss'),
                        ('zstdcat','zstd'),('scp','sftp'),('whatis','man'),
                        ('undo','buf'),('ldap','crypto'),('ntp','crypto')]:
    run('--include',name,'--show-config',ok=False)
    assert plan('--include',name+','+companion)['names']==[name,companion]
with tempfile.TemporaryDirectory() as d:
    f=Path(d)/'bash-loadables-selected.list'
    f.write_text('# exact list\n\n cut | quoted "help" with \\ and | separators \nseq')
    s=plan('--list',str(f))
    assert s['names']==['cut','seq'] and s['tag']=='selected'
    assert s['entries']['cut']=='quoted "help" with \\ and | separators'
    assert plan('--include-list',str(f))['names']==['cut','seq']
    assert plan('--profile','shell','--include-list',str(f))['names']==['cut','seq']
    resolved=run('--list',str(f),'--print-list').stdout
    f.write_text(resolved)
    assert plan('--list',str(f))['entries']==s['entries']
    for malformed in ['cut\ncut\n','cut\nBAD','cut\nfoo/bar','cut|a\tb','cut|a\vseq']:
        f.write_text(malformed)
        run('--list',str(f),'--print-list',ok=False)
    reusable=Path(d)/'bash-core.loadables.list'
    reusable.write_text('cut\nseq\n')
    assert plan('--list',str(reusable))['names']==['cut','seq']
    f.write_text('')
    assert plan('--list',str(f))['names']==[]
    f.write_text('greet|A greeting\n')
    environment=dict(os.environ,EXTRA_LOADABLES='docs/tutorial')
    assert plan('--list',str(f),env=environment)['names']==['greet']
    run('--list',str(f),'--print-list',ok=False)
run('--list-profiles','--print-list',ok=False)
run('--show-config','--list-loadables',ok=False)
run('--list-profiles')
run('--list-loadables')
run('--help')
print(f'profiles: {checks} selection checks passed')
