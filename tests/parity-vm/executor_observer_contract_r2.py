#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only admission rules for the ancestor-PID observer placement.

No executor wire protocol or verdict semantics are implemented here.
"""
import json
import uuid

ROOT = '/opt/bashos-parity'
HARNESS = ROOT + '/harness'
REFERENCES = ROOT + '/reference-data'
DRIVER = REFERENCES + '/executor/guest-executor-controls-ancestor-r2.py'
OBSERVER = REFERENCES + '/executor/executor-observer.py'
BASE = REFERENCES + '/privcmd/guest-privcmd-controls.py'
RECEIPT = REFERENCES + '/privcmd/privcmd-build-receipt.json'
ADDON = REFERENCES + '/executor/executor-observer-build-receipt.json'
OUTPUT = '/tmp/parity-home/authority-results'
EVAL_CGROUP = '/system.slice/parity-evaluation.service'
FAULTS = ('none', 'setgroups', 'setresgid', 'setresuid', 'capset', 'getresuid',
          'getresgid', 'mismatch-getresuid', 'mismatch-getresgid')
CASES = {v+'-'+f: {'fault':f, 'negative':None, 'executor':'executor-observed'}
         for v in ('auth','doas','sudo') for f in FAULTS}
CASES.update({'negative-continue-after-fault': {'fault':'setgroups','negative':'continue-after-fault','executor':'executor-bad-continue'},
              'negative-saved-root-id': {'fault':'none','negative':'saved-root-id','executor':'executor-bad-saved'}})
MNT, NET, PID, USER = 0x00020000, 0x40000000, 0x20000000, 0x10000000
NSFS = 0x6e736673
CGROUP2 = 0x63677270
CONFIG_MAX = 8192
FRAME_MAX = 8192


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def decode(raw):
    require(len(raw)<=FRAME_MAX, 'bounded JSON frame exceeded')
    def pairs(rows):
        d={}
        for k,v in rows:
            require(k not in d, 'duplicate JSON key');d[k]=v
        return d
    def invalid(value): raise RuntimeError('non-finite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def token(value):
    require(str(uuid.UUID(value))==value, 'canonical VM UUID required')
    return value


def directory(value): return '/run/bashos-executor-observer-'+token(value)
def unit(value): return 'bashos-executor-observer-'+token(value)+'.service'
def cgroup(value): return '/system.slice/'+unit(value)


def expected_argv(reg):
    return ['/usr/bin/python3','-B',DRIVER,'--receipt',RECEIPT,
            '--receipt-sha256',reg['files'][RECEIPT], '--expected-uuid',reg['token'],
            '--output',OUTPUT,'--bash',ROOT+'/candidate','--bash-sha256',reg['candidate_sha256'],
            '--observer-receipt',ADDON,'--observer-receipt-sha256',reg['files'][ADDON]]


def authorize_peer(peer, reg):
    require(type(peer['pid']) is int and peer['pid']>1 and peer['pid']==peer['nspid'][0], 'positive visible fixture PID required')
    require(peer['credentials']==[0,0] and peer['uids']==peer['gids']==[0]*4, 'root fixture credentials differ')
    require(peer['start']==peer['start_after'] and peer['start']>0 and peer['pidfd_live'] is True,
            'fixture exited/reused during admission')
    require(peer['exe_sha256']==reg['python_sha256'] and peer['argv']==expected_argv(reg) and
            peer['script_sha256']==reg['files'][DRIVER] and peer['cwd']=='/tmp/parity-case', 'pinned fixture image/argv/cwd differs')
    require(peer['cgroup']==EVAL_CGROUP and peer['user_ns']==reg['initial']['user'], 'fixture cgroup/user namespace differs')
    attest=peer['attestation']; evaluator=peer['evaluator']
    require(attest['schema']=='bashos-syslog-namespace-attestation-v1' and attest['token']==reg['token'] and
            attest['outer_namespaces']=={k:reg['initial'][k]['link'] for k in ('pid','net','mnt')}, 'evaluator attestation differs')
    require(len(peer['nspid'])==2 and peer['ns']['pid']['link']==attest['namespaces']['pid'] and
            peer['pid_ns_parent']==reg['initial']['pid'], 'fixture PID namespace is not the attested direct child')
    require(evaluator['nspid']==[evaluator['pid'],1] and evaluator['pid'] in peer['ancestor_pids'] and
            evaluator['pid_ns']==peer['ns']['pid'] and evaluator['exe_sha256']==reg['python_sha256'] and
            evaluator['script_sha256']==reg['files'][HARNESS+'/guest.py'] and
            evaluator['argv']==reg['evaluator_argv'] and evaluator['cgroup']==EVAL_CGROUP,
            'isolated evaluator PID1/script/lineage differs')
    for name,kind in (('mnt',MNT),('net',NET)):
        given=peer['descriptors'][name]
        require(given['fs_type']==NSFS and given['type']==kind and given['identity']==peer['ns'][name] and
                given['owner_user_ns']==reg['initial']['user'], 'namespace descriptor type/inode/owner differs: '+name)
        require(given['identity']!=reg['initial'][name] and
                given['identity']['link']!=attest['namespaces'][name], 'fixture namespace isolation missing: '+name)
    require(peer['output_matches'] is True and peer['output_root_owned_private'] is True, 'foreign/unprotected output directory')


def validate_config(case, config, reg, network):
    require(case in CASES, 'unregistered case')
    fixed=CASES[case]
    require(set(config)=={'fault','negative','uid','gid','groups','target','target_sha256','target_identity',
                         'executor_sha256','network_namespace'}, 'config key set differs')
    require(config['fault']==fixed['fault'] and config['negative']==fixed['negative'] and
            config['uid']==config['gid']==43202 and config['groups']==[43202,43204], 'case/control/credential selection differs')
    require(config['target']=='/var/lib/bashos-privcmd-v2-'+reg['token']+'/target-nopass' and
            config['target_sha256']==reg['target_sha256'] and
            config['executor_sha256']==reg['executors'][fixed['executor']], 'target/executor pin differs')
    require(isinstance(config['target_identity'],list) and len(config['target_identity'])==2 and
            all(type(n) is int and n>0 for n in config['target_identity']), 'target identity malformed')
    require(config['network_namespace']==network, 'config network namespace differs')


def ready(proof, initial, fixture_ns, worker_pid):
    require(proof['pid']==proof['proc_self_pid']==worker_pid and worker_pid>1 and
            proof['pid_ns']==proof['proc_init_pid_ns']==initial['pid'] and
            proof['user_ns']==initial['user'], 'ancestor active PID/procfs/user identity differs')
    require(proof['net_ns']==fixture_ns['net'] and proof['mnt_ns'] not in
            (fixture_ns['mnt'],initial['mnt']) and proof['private_mounts'] is True,
            'observer worker mount/network placement differs')
    require(proof['observer_bound'] is True, 'observer has not bound the private listener')


def ack(message, case, nonce):
    require(message=={'op':'ACK','case':case,'nonce':nonce}, 'ready ACK differs')


def completed(finished, status, cleanup):
    require(finished is True and type(status) is int and status==0 and
            cleanup=={'wait_status':0,'reaped':True,'forced':False},
            'observer incomplete or cleanup forced; killing an actor is not an abort observation')


def reaped_fdinfo(fields):
    return fields.get('Pid','').strip()=='-1' and fields.get('NSpid','').strip()=='-1'


def disposition(reached, observation_complete, cleanup_complete):
    """Data classification only. A transport error retains any reached FAIL."""
    require(reached in (None,'PASS','FAIL'),'invalid reached verdict')
    return {'status':reached if observation_complete is True and cleanup_complete is True and reached else 'ERROR',
            'retained_failure':reached=='FAIL','release_eligible':reached=='PASS' and
            observation_complete is True and cleanup_complete is True}
