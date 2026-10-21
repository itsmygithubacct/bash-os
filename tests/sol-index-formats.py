#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Git-written split/sparse indexes, all mutators, and atomic missing-base refusal."""
import argparse,hashlib,os,shlex,shutil,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);a=p.parse_args()
binary=str(Path(a.binary).resolve())
env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_AUTHOR_NAME='test',GIT_AUTHOR_EMAIL='test@example.invalid',GIT_COMMITTER_NAME='test',GIT_COMMITTER_EMAIL='test@example.invalid')
with tempfile.TemporaryDirectory(prefix='index-formats-') as d:
 root=Path(d)
 def git(repo,*args,data=None,index=None):
  e=dict(env);e.pop('LD_PRELOAD',None);e.pop('GIT_INDEX_FILE',None)
  if index:e['GIT_INDEX_FILE']=str(index)
  r=subprocess.run(['/usr/bin/git','-C',str(repo),*args],env=e,input=data,capture_output=True)
  assert r.returncode==0,(args,r.returncode,r.stderr)
  return r.stdout
 def run(repo,command,data=None):
  r=subprocess.run([binary,'--noprofile','--norc','-c','PATH=; index '+command],cwd=repo,env=env,input=data,capture_output=True)
  print(command,r.returncode,r.stderr.decode(errors='replace')[:1000],flush=True)
  assert b'AddressSanitizer' not in r.stderr and b'runtime error:' not in r.stderr,r.stderr
  return r
 def listing(repo,idx):
  return b''.join(row.replace(b'\t',b' ',1)+b'\n' for row in git(repo,'ls-files','--stage','-z',index=idx).split(b'\0') if row)
 for kind in ['split','split-config','sparse','sparse-packed','v4']:
  repo=root/kind;repo.mkdir();git(repo,'init','-q')
  for directory in ['keep','outside']:
   (repo/directory).mkdir()
   for i in range(80 if kind.startswith('split') else 3):(repo/directory/f'f{i}').write_text(f'{directory} {i}\n')
  git(repo,'add','.');git(repo,'commit','-qm','fixture')
  if kind.startswith('split'):
   if kind=='split-config':
    git(repo,'config','core.splitIndex','true');git(repo,'update-index','--refresh')
   else:git(repo,'update-index','--split-index')
   git(repo,'config','splitIndex.maxPercentChange','100')
   (repo/'keep/f0').write_text('replacement\n');git(repo,'add','keep/f0')
   git(repo,'update-index','--force-remove',*[f'outside/f{i}' for i in range(1,70)])
   (repo/'keep/new').write_text('new\n');git(repo,'add','keep/new')
   assert list((repo/'.git').glob('sharedindex.*'))
  elif kind.startswith('sparse'):
   git(repo,'sparse-checkout','init','--cone','--sparse-index');git(repo,'config','index.sparse','true');git(repo,'sparse-checkout','set','keep')
   assert b'sdir' in (repo/'.git/index').read_bytes()
   if kind=='sparse-packed':git(repo,'repack','-ad');git(repo,'prune-packed')
  else:git(repo,'update-index','--index-version=4')
  original=(repo/'.git/index').read_bytes();expected=listing(repo,repo/'.git/index')
  oid=git(repo,'hash-object','-w','--stdin',data=b'new blob\n').strip().decode()
  (repo/'keep/new-file').write_text('new blob\n')
  for verb in ['read','list','array','noop','write','add','remove','update-stat','index-info']:
   idx=repo/'.git/ours';idx.write_bytes(original);quoted=shlex.quote(str(idx))
   if verb=='array':command='read '+quoted+' -V rows; printf \"%s\\n\" \"${rows[@]}\"';data=None
   elif verb in ['read','list']:command=verb+' '+quoted;data=None
   elif verb=='noop':command='--index-info '+quoted;data=b''
   elif verb=='write':command='write '+quoted;data=expected
   elif verb=='add':command=f'add {quoted} {oid} keep/new-file';data=None
   elif verb=='remove':command=f'remove {quoted} outside/f0';data=None
   elif verb=='update-stat':command=f'update-stat {quoted} keep/f0';data=None
   else:command='--index-info '+quoted;data=f'100644 {oid}\toutside/new\n'.encode()
   stamp=idx.stat().st_mtime_ns;r=run(repo,command,data)
   assert r.returncode==0,(kind,verb,r.stderr)
   if verb in ['read','list','array']:assert r.stdout==expected,(kind,verb,r.stdout,expected)
   elif verb=='noop':assert idx.read_bytes()==original and idx.stat().st_mtime_ns==stamp
   else:
    want=expected
    if verb=='add':want+=f'100644 {oid} 0 keep/new-file\n'.encode()
    if verb=='remove':want=b''.join(x+b'\n' for x in expected.splitlines() if not x.endswith(b' outside/f0'))
    if verb=='index-info':want+=f'100644 {oid} 0 outside/new\n'.encode()
    got=listing(repo,idx)
    assert sorted(got.splitlines())==sorted(want.splitlines()),(kind,verb,got,want)
    rr=run(repo,'read '+quoted);assert rr.returncode==0 and rr.stdout==got
   assert not Path(str(idx)+'.lock').exists() and not list(idx.parent.glob('ours.tmp*'))
  idx=repo/'.git/ours';idx.write_bytes(original)
  oracle=repo/'.git/oracle';oracle.write_bytes(original)
  streams=[f'0 {"0"*40}\toutside/f0\n',f'100644 {oid} 2\tkeep/f0\n',f'100644 {oid}\tkeep/f0\n']
  for stream in streams:
   git(repo,'update-index','--index-info',index=oracle,data=stream.encode())
   r=run(repo,'--index-info '+shlex.quote(str(idx)),stream.encode());assert r.returncode==0
   assert listing(repo,idx)==listing(repo,oracle)
   assert git(repo,'ls-files','--resolve-undo','-z',index=idx)==git(repo,'ls-files','--resolve-undo','-z',index=oracle)
  if kind.startswith('split'):
   # Independently hide, then corrupt each private shared file. All changes
   # must refuse before installing a replacement; every original byte survives.
   shared={p:p.read_bytes() for p in (repo/'.git').glob('sharedindex.*')}
   for broken in ['missing','truncated','corrupt','wrong-name']:
    for path,raw in shared.items():
     if broken=='missing':path.unlink()
     elif broken=='truncated':path.write_bytes(raw[:12])
     else:
      changed=bytearray(raw);changed[12]^=1
      if broken=='wrong-name':changed[-20:]=hashlib.sha1(changed[:-20]).digest()
      path.write_bytes(changed)
    for verb in ['read','write','add','remove','update-stat','index-info']:
     idx=repo/'.git/ours';idx.write_bytes(original);q=shlex.quote(str(idx))
     command={'write':'write '+q,'read':'read '+q,'add':f'add {q} {oid} keep/new-file','remove':f'remove {q} keep/f0','update-stat':f'update-stat {q} keep/f0','index-info':'--index-info '+q}[verb]
     r=run(repo,command,expected if verb=='write' else f'100644 {oid}\tx\n'.encode() if verb=='index-info' else None)
     assert r.returncode!=0 and idx.read_bytes()==original,(kind,broken,verb)
     assert not Path(str(idx)+'.lock').exists() and not list(idx.parent.glob('ours.tmp*'))
    for path,raw in shared.items():path.write_bytes(raw)
  print('PASS',kind,flush=True)

with tempfile.TemporaryDirectory(prefix='index-directory-import-') as d:
 repo=Path(d);git(repo,'init','-q')
 oid=git(repo,'hash-object','-w','--stdin',data=b'child\n').strip()
 tree=git(repo,'mktree',data=b'100644 blob '+oid+b'\tf\n').strip()
 stream=b'040000 '+tree+b'\td\n'
 oracle=repo/'.git/oracle';ours=repo/'.git/ours'
 git(repo,'update-index','--index-info',index=oracle,data=stream)
 r=run(repo,'--index-info '+shlex.quote(str(ours)),stream)
 assert r.returncode==0 and ours.read_bytes()==oracle.read_bytes()
 r=run(repo,'read '+shlex.quote(str(ours)))
 assert r.returncode==0 and r.stdout==listing(repo,oracle),(r.stdout,r.stderr)
 print('PASS directory import and tree expansion',flush=True)
