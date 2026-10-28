#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contained mount propagation controls using only remembered guest children."""
import base64
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

CASE=Path('/tmp/parity-case');HOME=Path('/tmp/parity-home')


def guard():
    uuid.UUID(Path('/etc/bashos-parity-vm').read_text().strip())
    mapping=[list(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    if (Path('/sys/class/dmi/id/sys_vendor').read_text().strip()!='QEMU' or os.getuid()!=0 or os.geteuid()!=0 or
        mapping!=[[0,2000,1]] or Path.cwd()!=CASE or os.environ.get('HOME')!=str(HOME) or
        not os.environ.get('FIXTURE_OUTER_MNT') or os.readlink('/proc/self/ns/mnt')==os.environ['FIXTURE_OUTER_MNT']):
        raise RuntimeError('private mapped-user guest namespace required')
    virt=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    if virt not in ('qemu','kvm'):raise RuntimeError('not a disposable QEMU/KVM guest')


def save(name,data): (HOME/name).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')


def mount_call(source,target,kind,flags,data=None):
    lib=ctypes.CDLL(None,use_errno=True);ctypes.set_errno(0)
    rc=lib.mount(ctypes.c_char_p(os.fsencode(source)) if source else None,ctypes.c_char_p(os.fsencode(target)),
                 ctypes.c_char_p(os.fsencode(kind)) if kind else None,ctypes.c_ulong(flags),
                 ctypes.c_char_p(os.fsencode(data)) if data else None)
    return {'source':source,'target':target,'kind':kind,'flags':flags,'data':data,
            'result':int(rc),'errno':ctypes.get_errno() if rc<0 else 0}


def snapshot(pid='self'):
    path=Path('/proc')/str(pid);raw=(path/'mountinfo').read_text()
    if len(raw)>512*1024:raise RuntimeError('mountinfo exceeds bound')
    root=[];mountpoints=[];shared_mountpoints=[]
    for line in raw.splitlines():
        left,sep,_=line.partition(' - ')
        fields=left.split()
        if not sep or len(fields)<6:raise RuntimeError('bad mountinfo row')
        mountpoints.append(fields[4])
        if any(item.startswith('shared:') for item in fields[6:]): shared_mountpoints.append(fields[4])
        if fields[4]=='/':root.append({'mount_id':fields[0],'parent_id':fields[1],'options':fields[5],'optional':fields[6:]})
    if len(root)!=1:raise RuntimeError('unexpected root mount count')
    return {'pid':pid,'namespace':os.readlink(path/'ns/mnt'),'raw_mountinfo':raw,
            'root':root[0],'mountpoints':mountpoints,'shared_mountpoints':shared_mountpoints,'status':(path/'status').read_text()}


def category(info):
    tags=info['root']['optional']
    shared=any(x.startswith('shared:') for x in tags)
    master=any(x.startswith('master:') for x in tags)
    if shared:return 'shared'
    if master:return 'slave'
    return 'private'


def capture(args):
    p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err=p.communicate(timeout=12)
    if len(out)>128*1024 or len(err)>128*1024:raise RuntimeError('output bound exceeded')
    return {'argv':args,'pid':p.pid,'status':p.returncode,'stdout_base64':base64.b64encode(out).decode(),
            'stderr_base64':base64.b64encode(err).decode()}


def hold():
    print('READY',flush=True)
    if sys.stdin.readline().strip()!='done':raise RuntimeError('owned child release missing')


def start_shared(report):
    report['initial']=snapshot()
    if category(report['initial'])!='private' or report['initial']['shared_mountpoints']:
        raise RuntimeError('outer unshare did not start recursively private')
    report['make_shared']=mount_call(None,'/',None,(1<<20)|(1<<14))
    if report['make_shared']['result']!=0:raise RuntimeError('make-shared failed')
    report['shared']=snapshot()
    if category(report['shared'])!='shared':raise RuntimeError('parent root is not shared')


def shell(binary,command):
    script=r'''[[ $UID == 0 && $EUID == 0 && $PWD == /tmp/parity-case && $HOME == /tmp/parity-home ]] || exit 125
IFS= read -r marker </etc/bashos-parity-vm || exit 125
IFS= read -r vendor </sys/class/dmi/id/sys_vendor || exit 125
[[ $vendor == QEMU && $marker =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || exit 125
mapfile -t maps </proc/self/uid_map || exit 125
(( ${#maps[@]} == 1 )) || exit 125
read -r a b n tail <<<"${maps[0]}"; [[ $a == 0 && $b == 2000 && $n == 1 && -z $tail ]] || exit 125
virt=$(/usr/bin/systemd-detect-virt --vm) || exit 125
[[ $virt == qemu || $virt == kvm ]] || exit 125
'''+command
    return [binary,'--noprofile','--norc','-c',script]


def isolation(mode,binary=None):
    report={'mode':mode};child=None
    try:
        start_shared(report)
        child=subprocess.Popen(['/usr/bin/unshare','--mount','--propagation','unchanged','/usr/bin/python3',__file__,'hold'],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if child.stdout.readline()!='READY\n':raise RuntimeError('owned sibling did not become ready')
        report['sibling_pid']=child.pid;report['sibling_before']=snapshot(child.pid)
        if report['sibling_before']['namespace']==report['shared']['namespace'] or category(report['sibling_before'])!='shared':
            raise RuntimeError('shared sibling mount namespace control failed')
        pre=CASE/('prop-'+mode+'-pre');post=CASE/('prop-'+mode+'-post');pre.mkdir();post.mkdir()
        report['pre_mount']=mount_call('fixture',str(pre),'tmpfs',0,'size=1m')
        if report['pre_mount']['result']!=0:raise RuntimeError('control tmpfs mount failed')
        report['sibling_after_pre']=snapshot(child.pid)
        if str(pre) not in report['sibling_after_pre']['mountpoints']:
            raise RuntimeError('shared propagation positive control failed')
        if mode=='control': report['command']=capture(['/usr/bin/mount','--make-rprivate','/'])
        elif mode=='run':report['command']=capture(shell(binary,'[[ $(type -t ns) == builtin ]] || exit 99\nns mount-private\n'))
        else:raise ValueError('unknown mode')
        report['after_private']=snapshot()
        report['post_mount']=mount_call('fixture',str(post),'tmpfs',0,'size=1m')
        report['parent_after']=snapshot();report['sibling_after']=snapshot(child.pid)
        report['checks']={'command_ok':report['command']['status']==0,'private':category(report['after_private'])=='private',
                          'post_mount_ok':report['post_mount']['result']==0,
                          'post_parent_visible':str(post) in report['parent_after']['mountpoints'],
                          'post_sibling_absent':str(post) not in report['sibling_after']['mountpoints'],
                          'sibling_pre_retained':str(pre) in report['sibling_after']['mountpoints']}
        save('isolation-'+mode+'.json',report)
        if not all(report['checks'].values()):raise RuntimeError('propagation isolation mismatch')
        if mode=='run':print('propagation-isolation=verified')
    except Exception as exc:
        report['fatal_error']=str(exc);save('isolation-'+mode+'.json',report);raise
    finally:
        if child is not None:
            if child.poll() is None:
                try:child.stdin.write('done\n');child.stdin.flush()
                except (OSError,BrokenPipeError):pass
            child.wait(timeout=5)
            if child.returncode!=0:raise RuntimeError('owned sibling did not exit normally')


def capture_child(label):
    info=snapshot();info['category']=category(info);save('spawn-'+label+'.json',info)


def spawn_modes(mode,binary=None):
    report={'mode':mode,'calls':{}}
    try:
        start_shared(report);parent_ns=report['shared']['namespace']
        for flag in ('private','slave','shared'):
            native=capture(['/usr/bin/unshare','--mount','--propagation',flag,'/usr/bin/python3',__file__,'capture','native-'+flag])
            child=json.loads((HOME/('spawn-native-'+flag+'.json')).read_text()) if native['status']==0 else None
            report['calls'][flag]={'native':native,'native_child':child}
            if native['status']!=0 or child['category']!=flag or child['namespace']==parent_ns:
                raise RuntimeError('native propagation control failed: '+flag)
            if mode=='run':
                command='[[ $(type -t ns) == builtin ]] || exit 99\nns spawn --propagation '+flag+' mount /usr/bin/python3 '+__file__+' capture candidate-'+flag+'\n'
                candidate=capture(shell(binary,command))
                path=HOME/('spawn-candidate-'+flag+'.json')
                observed=json.loads(path.read_text()) if path.exists() else None
                report['calls'][flag].update(candidate=candidate,candidate_child=observed)
            report['calls'][flag]['parent_after']=snapshot()
        report['checks']={}
        for flag,item in report['calls'].items():
            report['checks'][flag+'-parent-unchanged']=(item['parent_after']['namespace']==parent_ns and item['parent_after']['root']==report['shared']['root'])
            if mode=='run':
                data=item['candidate_child']
                report['checks'][flag+'-candidate']=(item['candidate']['status']==0 and data is not None and data['category']==flag and data['namespace']!=parent_ns)
        save('spawn-modes-'+mode+'.json',report)
        if not all(report['checks'].values()):raise RuntimeError('spawn propagation mismatch')
        if mode=='run':print('spawn-propagation=verified')
    except Exception as exc:
        report['fatal_error']=str(exc);save('spawn-modes-'+mode+'.json',report);raise


def main():
    guard();mode=sys.argv[1]
    if mode=='hold':hold()
    elif mode=='capture':capture_child(sys.argv[2])
    elif mode=='isolation':isolation(sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
    elif mode=='spawn-modes':spawn_modes(sys.argv[2],sys.argv[3] if len(sys.argv)>3 else None)
    else:raise ValueError('unknown mode')


if __name__=='__main__':main()
