#!/usr/bin/env python3
"""Validated private AF_UNIX delivery timing; no external ratio or host syslog.

Run through the campaign bench gate. Build the binary separately through its
build gate. Each pass validates every datagram and the sender's final status.
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
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, default=ROOT/'out/bash-sol-bashlogger')
parser.add_argument('--count', type=int, default=5000)
parser.add_argument('--runs', type=int, default=9)
parser.add_argument('--cpu', type=int)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if args.runs < 7 or args.count < 1:
    parser.error('at least seven samples and a positive message count are required')
allowed = os.sched_getaffinity(0)
cpu = args.cpu if args.cpu is not None else max(allowed)
if cpu not in allowed:
    parser.error('CPU is outside the available affinity')
os.sched_setaffinity(0, {cpu})
binary = str(args.binary.resolve())
script = '''PATH=
printf 'ready\\n'
read -r go || exit 90
for ((i=0;i<COUNT;i++)); do
  bashlogger -p local0.info -t bench record "$i" payload-0123456789abcdef || exit 91
done
printf '%d\\n' "$i"
'''.replace('COUNT', str(args.count))
fixture = dict(count=args.count, priority='local0.info', numeric_priority=134, tag='bench',
               message_arguments=['record', '<decimal index starting at 0>', 'payload-0123456789abcdef'],
               expected='<134> bench: record {index} payload-0123456789abcdef',
               script=script, reset='fresh shell and private socket per pass, drain all messages')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_pass(index):
    import socket
    with tempfile.TemporaryDirectory(prefix='blog-bench-') as directory:
        path = str(Path(directory)/'log')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
            receiver.bind(path)
            receiver.settimeout(15)
            received = []
            errors = []
            def drain():
                try:
                    for i in range(args.count):
                        packet = receiver.recv(65536)
                        expected = f'<134> bench: record {i} payload-0123456789abcdef'.encode()
                        if packet != expected:
                            errors.append(f'packet {i}: {packet!r} != {expected!r}')
                        received.append(len(packet))
                except Exception as error:
                    errors.append(repr(error))
            env = dict(os.environ, PATH='', LC_ALL='C', BASHLOGGER_SOCKET=path)
            for name in ('BASH_ENV', 'LD_PRELOAD', 'BLOG_TEST_MODE'):
                env.pop(name, None)
            worker = threading.Thread(target=drain, daemon=True)
            proc = subprocess.Popen([binary, '--noprofile', '--norc', '-c', script],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env)
            try:
                ready = proc.stdout.readline()
                if ready != b'ready\n':
                    raise RuntimeError(f'sender failed to become ready: {ready!r}')
                worker.start()
                started = time.perf_counter_ns()
                stdout, stderr = proc.communicate(b'go\n', timeout=30)
                worker.join(timeout=20)
                elapsed = time.perf_counter_ns() - started
                receiver.setblocking(False)
                try:
                    extra = receiver.recv(65536)
                    errors.append(f'extra packet: {extra!r}')
                except BlockingIOError:
                    pass
                valid = (not worker.is_alive() and not errors and len(received) == args.count
                         and proc.returncode == 0 and stdout == f'{args.count}\n'.encode() and not stderr)
                result = dict(pass_index=index, role='warmup' if index == -1 else 'sample',
                              status='passed' if valid else 'failed', elapsed_ns=elapsed,
                              sent=args.count, received=len(received), bytes_received=sum(received),
                              exit_code=proc.returncode, stdout=stdout.decode(errors='replace'),
                              stderr=stderr.decode(errors='replace'), errors=errors)
                print(f"{result['role']} {index}: {result['status']}, {len(received)} messages, {elapsed/1e6:.3f} ms", flush=True)
                return result
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.communicate()

report = dict(workload='bashlogger-private-datagrams', kind='api', reference=None,
              ratio=None, fixture=fixture,
              fixture_sha256=hashlib.sha256(json.dumps(fixture, sort_keys=True).encode()).hexdigest(),
              source_sha256=sha(ROOT/'loadables/bashlogger.c'), binary_sha256=sha(binary),
              harness_sha256=sha(__file__),
              source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              working_tree_diff_sha256=hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD', '--', 'loadables/bashlogger.c'], cwd=ROOT)).hexdigest(),
              environment=dict(python=sys.version, platform=platform.platform(), machine=platform.machine(),
                               cpu_affinity=sorted(os.sched_getaffinity(0)),
                               cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), None),
                               bash=subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
                               compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                               path='', locale='C', clock='perf_counter_ns'),
              timing='release ready sender through validated receiver drain and shell exit; Python receiver on the same CPU',
              limitations=['API wall time includes shell loop, syscalls, Python drain/validation and scheduling; no external ratio.',
                           'Private AF_UNIX datagram transport only; no host syslog daemon or persistence is exercised.'],
              passes=[])
try:
    for i in [-1, *range(args.runs)]:
        result = run_pass(i)
        report['passes'].append(result)
        if result['status'] != 'passed':
            raise RuntimeError(f'validation failed in pass {i}')
    samples = [p['elapsed_ns'] for p in report['passes'] if p['role'] == 'sample']
    report.update(status='passed', samples_ns=samples,
                  distribution_ns=dict(min=min(samples), max=max(samples), median=statistics.median(samples),
                                       mean=statistics.mean(samples), stdev=statistics.stdev(samples)),
                  messages_per_second=args.count/(statistics.median(samples)/1e9))
except Exception as error:
    report.update(status='failed', error=repr(error))
finally:
    args.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({key: report[key] for key in ('status', 'distribution_ns', 'messages_per_second') if key in report}))
raise SystemExit(report['status'] != 'passed')
