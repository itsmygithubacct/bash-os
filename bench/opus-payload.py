#!/usr/bin/env python3
"""Self-timed payload helper transactions on a private repo and root.

One sample is one bash-os process running TXNS iterations of
`payload install NAME && payload remove NAME` against the recording fake
bl-pkg.sh from tests/opus-payload-installer.py, so each sample performs
2*TXNS helper fork/exec round trips plus TXNS INDEX scans (RECORDS records)
and TXNS state-file transaction lookups. Every sample, warm-up included, is
validated: exact stdout, exit 0, exactly 2*TXNS recorded helper argv vectors
with the production shape, and an empty install state afterwards. There is no
external comparator, so no ratio is reported. Run through the bench gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

here = Path(__file__).resolve().parent

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', default='out/bash-opus-payload')
parser.add_argument('--runs', type=int, default=7)
parser.add_argument('--txns', type=int, default=20)
parser.add_argument('--records', type=int, default=2000)
parser.add_argument('--cpu', type=int, default=2)
parser.add_argument('--output', required=True)
args = parser.parse_args()
binary = Path(args.binary).resolve()


def fake_source():
    # Reuse the exact fake from the integration test without running the test.
    text = (here.parent / 'tests/opus-payload-installer.py').read_text()
    start = text.index("FAKE = r'''") + len("FAKE = r'''")
    return text[start:text.index("'''", start)]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


with tempfile.TemporaryDirectory(prefix='opus-payload-bench-') as d:
    top = Path(d)
    repo, root, log = top / 'repo', top / 'root', top / 'log'
    state = root / 'var/lib/bl-pkg/installed'
    for p in (repo, state, log):
        p.mkdir(parents=True)
    helper = top / 'bl-pkg.sh'
    helper.write_text(fake_source())
    index = ''.join('blpkg-v1 name=pl-%05d version=1.%d.0 arch=x86_64 provides=bin/pl-%05d\n'
                    % (i, i % 53, i) for i in range(args.records))
    (repo / 'INDEX').write_text(index)
    target = 'pl-%05d' % (args.records - 1)          # forces a full INDEX scan
    script = ('for ((i=0;i<%d;i++)); do payload install %s && payload remove %s || exit 1; done'
              % (args.txns, target, target))
    env = {'LC_ALL': 'C', 'PATH': '', 'HOME': str(top), 'PAYLOAD_REPO': str(repo),
           'PAYLOAD_ROOT': str(root), 'PAYLOAD_INSTALLER': str(helper), 'FAKE_LOG': str(log)}
    expected = ''.join('helper: installed %s\nhelper: rolled back txn-%s-%d\n'
                       'payload: removed %s\n' % (target, target, 2 * i, target)
                       for i in range(args.txns))
    base = [str(binary), str(helper), '--internal', '--root', str(root)]

    def one():
        for f in log.iterdir():
            f.unlink()
        t0 = time.perf_counter()
        r = subprocess.run([str(binary), '--norc', '--noprofile', '-c', script], env=env,
                           capture_output=True, text=True, timeout=300,
                           preexec_fn=lambda: os.sched_setaffinity(0, {args.cpu}))
        elapsed = (time.perf_counter() - t0) * 1000
        calls = sorted(log.glob('call.*'), key=lambda p: int(p.suffix[1:]))
        argvs = [[a.decode() for a in c.read_bytes().split(b'\0')[:-1]] for c in calls]
        want = []
        for i in range(args.txns):
            want.append(base + ['--repo', str(repo), '--allow-unsigned', 'install', target])
            want.append(base + ['rollback', 'txn-%s-%d' % (target, 2 * i)])
        ok = (r.returncode == 0 and r.stdout == expected and r.stderr == ''
              and argvs == want and not any(state.iterdir()))
        return elapsed, ok, r

    warm = one()
    samples, valid = [], [warm[1]]
    for _ in range(args.runs):
        ms, ok, r = one()
        samples.append(round(ms, 3))
        valid.append(ok)
    report = {
        'workload': 'payload-helper-transactions',
        'kind': 'self',
        'work_unit': ('%d x (payload install + payload remove) of the last of %d INDEX records '
                      'in one shell: %d helper fork/exec round trips, %d full INDEX scans, '
                      '%d state txn lookups' % (args.txns, args.records, 2 * args.txns,
                                                args.txns, args.txns)),
        'valid_every_pass': all(valid),
        'warmup_valid': warm[1],
        'samples_ms': samples,
        'median_ms': statistics.median(samples),
        'min_ms': min(samples), 'max_ms': max(samples),
        'stdev_ms': statistics.stdev(samples) if len(samples) > 1 else 0.0,
        'cpu_affinity': [args.cpu],
        'binary': str(binary), 'binary_sha256': sha(binary),
        'source_sha256': sha(here.parent / 'loadables/payload.c'),
        'fake_helper_sha256': hashlib.sha256(fake_source().encode()).hexdigest(),
        'index_sha256': hashlib.sha256(index.encode()).hexdigest(),
        'kernel': platform.release(), 'machine': platform.machine(),
        'python': sys.version.split()[0],
    }
    if not warm[1] or not all(valid):
        report['failure_sample'] = {'rc': warm[2].returncode, 'stderr': warm[2].stderr[:2000]}
    Path(args.output).write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({k: report[k] for k in ('valid_every_pass', 'median_ms', 'samples_ms')}))
    raise SystemExit(0 if report['valid_every_pass'] else 1)
