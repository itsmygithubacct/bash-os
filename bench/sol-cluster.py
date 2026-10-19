#!/usr/bin/env python3
"""Validated loopback membership API timings; run through the campaign bench gate.

There is no equivalent external cluster API, so these cases have no speed ratio.
The historical file-streaming case remains in unchanged bench/loadables.py.
"""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
from pathlib import Path
import platform
import shlex
import socket
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cluster_fixture', ROOT/'tests/sol-cluster-membership.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def wait_roster(peers, expected, timeout=2):
    end = time.monotonic() + timeout
    while not f.roster_is(peers, expected):
        if time.monotonic() >= end:
            raise TimeoutError('membership convergence timeout')
        time.sleep(.001)


def streaming(binary, before_binary, output, runs):
    """Same historical roster; validate every byte on every timed batch."""
    rows = ['node-%05d-0000-4000-8000-000000000000 10.%d.%d.%d:5450 '
            '/etc/cluster/keys/node-%05d.key'
            % (i, i//65536 % 256, i//256 % 256, i % 256, i) for i in range(20000)]
    expected = ('\n'.join(rows)+'\n').encode()
    passes = 40
    implementations = {'after': (binary, 'cluster members'),
                       'external': (binary, '/usr/bin/cat clusterstate/members')}
    if before_binary:
        implementations['before'] = (before_binary.resolve(strict=True), 'cluster members')
    report = dict(kind='compared', status='running', fixture_bytes=len(expected),
                  fixture_sha256=hashlib.sha256(expected).hexdigest(), passes=passes, runs=runs,
                  warmup_samples=1, cpus=sorted(os.sched_getaffinity(0)), kernel=platform.release(),
                  source_sha256=sha(ROOT/'loadables/cluster.c'),
                  source_tree_dirty=bool(subprocess.check_output(['git','status','--porcelain'], cwd=ROOT)),
                  work_unit='40 complete streams of the same 20,000-row roster per batch',
                  method='wall time including shell startup and private file capture; exact per-pass bytes checked outside each timer; warm page cache; rotating order',
                  external_version=subprocess.check_output(['/usr/bin/cat','--version'],text=True).splitlines()[0],
                  external_sha256=sha('/usr/bin/cat'),
                  implementations={})
    try:
        with tempfile.TemporaryDirectory(prefix='sol-cluster-stream-') as tmp:
            directory=Path(tmp); (directory/'clusterstate').mkdir(mode=0o700)
            (directory/'clusterstate/members').write_bytes(expected)
            for name,(exe,_) in implementations.items():
                report['implementations'][name]=dict(binary=str(exe),binary_sha256=sha(exe),
                                                     samples_ms=[],validated_passes=0,status='running')
            names=list(implementations)
            for sample in range(runs+1):
                order=names[sample%len(names):]+names[:sample%len(names)]
                for name in order:
                    exe,command=implementations[name]
                    script=f'for ((i=0;i<{passes};i++)); do {command} || exit; done'
                    with tempfile.TemporaryFile() as capture:
                        started=time.perf_counter_ns()
                        proc=subprocess.run([str(exe),'--noprofile','--norc','-c',script],cwd=directory,
                                            env={'PATH':'','LC_ALL':'C','BASHCLUSTER_STATE_DIR':'clusterstate'},
                                            stdout=capture,stderr=subprocess.PIPE,timeout=10)
                        elapsed=(time.perf_counter_ns()-started)/1e6
                        assert proc.returncode==0, (name,proc.returncode,proc.stderr)
                        assert capture.tell()==len(expected)*passes, (name,capture.tell())
                        with mmap.mmap(capture.fileno(),0,access=mmap.ACCESS_READ) as view:
                            for i in range(passes):
                                assert view[i*len(expected):(i+1)*len(expected)]==expected,(name,sample,i)
                    row=report['implementations'][name]
                    row['validated_passes']+=passes
                    if sample: row['samples_ms'].append(elapsed)
            for row in report['implementations'].values():
                row.update(status='ok',median_ms=statistics.median(row['samples_ms']),
                           min_ms=min(row['samples_ms']),max_ms=max(row['samples_ms']))
            report['after_over_external']=report['implementations']['after']['median_ms']/report['implementations']['external']['median_ms']
            report['status']='ok'
    except Exception as error:
        report.update(status='failed',error=repr(error))
        raise
    finally:
        output.write_text(json.dumps(report,indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--streaming-report', type=Path, help='also run strict offline roster comparisons first')
    parser.add_argument('--before-binary', type=Path)
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--joins', type=int, default=8)
    parser.add_argument('--pings', type=int, default=100)
    args = parser.parse_args()
    assert args.runs >= 7 and args.joins > 0 and args.pings > 0
    binary = args.binary.resolve(strict=True)
    if args.streaming_report:
        streaming(binary, args.before_binary, args.streaming_report, args.runs)
    fixture = dict(peers=3, transport='IPv4 UDP 127.0.0.1', timeout_ms=200,
                   capacity=32, heartbeat_ms=50, expiry_ms=600,
                   key='generated 256-bit shared key; unique nodes and ephemeral ports each fixture',
                   reset='third peer leaves before each join; verify 3-member add and 2-member remove on seed and observer',
                   oracle='exact node->endpoint map constructed from independent peer statuses; all ping lines and statuses checked')
    report = dict(schema=1, kind='api', external_reference=None, ratio=None,
                  binary=str(binary), binary_sha256=sha(binary),
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'], text=True, cwd=ROOT).strip(),
                  source_sha256=sha(ROOT/'loadables/cluster.c'),
                  source_tree_dirty=bool(subprocess.check_output(['git','status','--porcelain'], cwd=ROOT)),
                  harness_sha256=sha(__file__), fixture_harness_sha256=sha(ROOT/'tests/sol-cluster-membership.py'),
                  fixture=fixture, fixture_sha256=hashlib.sha256(json.dumps(fixture, sort_keys=True).encode()).hexdigest(),
                  runs=args.runs, joins_per_sample=args.joins, pings_per_sample=args.pings,
                  warmup_samples=1, cpus=sorted(os.sched_getaffinity(0)),
                  kernel=platform.release(), architecture=platform.machine(), python=sys.version,
                  bash_version=subprocess.check_output([binary,'--version'], text=True).splitlines()[0],
                  cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), None),
                  method='perf_counter_ns wall time; fixed pinned CPU inherited by all peers; join and ping exclude shell startup; updates include polling and snapshot IO; no external ratio',
                  cases={name: dict(samples_ms=[], operations_ms=[], attempts=0, successes=0,
                                    unexpected_timeouts=0, failures=0, expected_timeouts=0, errors=[])
                         for name in ('join','ping','membership-add','membership-remove','ping-blackhole')})
    report['versions'] = {'compiler': subprocess.check_output(['cc','--version'], text=True).splitlines()[0]}
    def record(name, elapsed, operations, warmup):
        if not warmup:
            row=report['cases'][name]; row['samples_ms'].append(elapsed)
            row['operations_ms'].extend(operations); row['attempts'] += len(operations)
            row['successes'] += len(operations)
    try:
        with tempfile.TemporaryDirectory(prefix='sol-cluster-bench-') as tmp, f.peers(binary, tmp) as (a,b,c):
            a.init(); b.join(a)
            base = {p.info['node_id']: p.endpoint for p in (a,b)}
            wait_roster((a,b), base)
            # Save realized fixture provenance too; dynamic IDs/ports are not work inputs.
            report['realized_seed_cluster'] = a.info['cluster_id']
            report['realized_rosters'] = []
            for sample in range(args.runs+1):
                warmup = sample == 0
                joins=[]; adds=[]; removes=[]
                for operation in range(args.joins):
                    started = time.perf_counter_ns()
                    out = c.command('join', a.endpoint, '-k', a.directory/'private_key')
                    joined = time.perf_counter_ns()
                    assert out.startswith('joined\n'), out
                    c.info = c.status(); c.endpoint = '127.0.0.1:' + c.info['port']
                    assert c.info['state'] == 'initialized' and c.info['cluster_id'] == a.info['cluster_id']
                    assert c.info['node_id'] not in base
                    expected = {**base, c.info['node_id']: c.endpoint}
                    report['realized_rosters'].append(dict(sample=sample, operation=operation, expected=expected))
                    wait_roster((a,b,c), expected)
                    updated = time.perf_counter_ns()
                    joins.append((joined-started)/1e6); adds.append((updated-started)/1e6)
                    left = time.perf_counter_ns()
                    assert c.command('leave') == 'left cluster\n'
                    wait_roster((a,b), base)
                    assert c.status()['state'] == 'uninitialized' and c.members() == {}
                    removes.append((time.perf_counter_ns()-left)/1e6)
                record('join',sum(joins),joins,warmup)
                record('membership-add',sum(adds),adds,warmup)
                record('membership-remove',sum(removes),removes,warmup)
                script = f'for ((i=0;i<{args.pings};i++)); do cluster ping {shlex.quote(b.endpoint)} || exit 79; done'
                started=time.perf_counter_ns(); output=a.call(script)
                elapsed=(time.perf_counter_ns()-started)/1e6
                assert output == f'ok {b.endpoint}\n'*args.pings, output
                # Batch timing is measured directly; no fabricated per-RPC samples.
                if not warmup:
                    row=report['cases']['ping']; row['samples_ms'].append(elapsed)
                    row['attempts']+=args.pings; row['successes']+=args.pings
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
                    silent.bind(('127.0.0.1',0)); endpoint=f'127.0.0.1:{silent.getsockname()[1]}'
                    started=time.perf_counter_ns()
                    output=a.command('ping',endpoint,rc=1,timeout=1)
                    elapsed=(time.perf_counter_ns()-started)/1e6
                    assert 'timed out' in output, output
                    assert 150 <= elapsed < 900, elapsed
                    if not warmup:
                        row=report['cases']['ping-blackhole']; row['samples_ms'].append(elapsed)
                        row['attempts']+=1; row['expected_timeouts']+=1
                assert f.roster_is((a,b),base)
        for name,row in report['cases'].items():
            row['status']='ok'
            row['median_batch_ms']=statistics.median(row['samples_ms'])
            row['min_batch_ms']=min(row['samples_ms']); row['max_batch_ms']=max(row['samples_ms'])
            row['work_unit'] = (f'{args.pings} authenticated request/reply pings' if name=='ping' else
                                'one deliberately unanswered authenticated ping' if name=='ping-blackhole' else
                                f'{args.joins} validated {name} transitions with 2 persistent peers')
            row['request_loss'] = row['attempts'] - row['successes']
            row['request_loss_rate'] = row['request_loss'] / row['attempts']
        report['status']='ok'
    except Exception as error:
        # Preserve failed validation rather than emitting an apparently successful timing.
        report['status']='failed'; report['error']=repr(error)
        for row in report['cases'].values():
            row['status']='invalid'; row['failures']+=1; row['errors'].append(repr(error))
            if isinstance(error, TimeoutError) or 'deadline' in str(error) or 'timed out' in str(error): row['unexpected_timeouts']+=1
        raise
    finally:
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({name: {key: row[key] for key in ('status','median_batch_ms','attempts','successes','request_loss','expected_timeouts','unexpected_timeouts','failures')}
                      for name,row in report['cases'].items()},indent=2))


if __name__ == '__main__':
    main()
