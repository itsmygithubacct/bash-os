#!/usr/bin/env python3
"""Validated private mail boundary timings. Run only through the bench gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mail_fixture', ROOT/'tests/sol-mail-check.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--source', type=Path, default=ROOT/'loadables/mail.c')
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--messages', type=int, default=16)
    args = ap.parse_args()
    assert args.runs >= 7 and args.messages > 0
    binary = args.binary.resolve()
    # Fixed independent wire oracle, including dot transparency and mixed LF/CRLF.
    payload = b'Subject: controlled delivery\r\nX-Fixture: sol-mail\r\n\r\n'+(b'.first\n..second\r\n'+b'x'*110+b'\n')*128+b'last'
    expected = m.canonical(payload)
    report = dict(kind='api', reference=None, external_ratio=None,
                  binary=str(binary), binary_sha256=sha(binary),
                  source_sha256=sha(args.source),
                  harness_sha256=sha(__file__), fixture_helper_sha256=sha(ROOT/'tests/sol-mail-check.py'),
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                  environment=dict(affinity=sorted(os.sched_getaffinity(0)), platform=platform.platform(),
                                   python=platform.python_version(),
                                   bash=subprocess.check_output([binary, '--version'], text=True).splitlines()[0],
                                   compiler=subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
                                   cpu=next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')), 'unknown')),
                  fixture=dict(input_sha256=hashlib.sha256(payload).hexdigest(),
                               received_sha256=hashlib.sha256(expected).hexdigest(),
                               input_bytes=len(payload), delivered_bytes=len(expected), messages_per_sample=args.messages,
                               sender=m.FROM, recipients=m.RCPTS, tls='off', timeout_ms=1000),
                  method=dict(warmups=1, timed_samples=args.runs, clock='perf_counter_ns',
                              reset='Fresh private queue, client shell and daemon per boundary/sample; fixture file prepared outside timing.',
                              latency='Per message Python request through persistent empty-PATH shell to successful status. SMTP includes loopback connect, DATA acknowledgement, QUIT and sink join; validations occur before a sample is accepted.',
                              throughput='Fixed message count divided by sum of per-message boundary latencies; excludes fixture setup and between-message queue/content validation.',
                              boundaries={'direct_enqueue':'client request -> atomic private queue install + queue-ID response',
                                          'unix_enqueue':'client request -> Unix submission daemon queue install + queue-ID response',
                                          'smtp_delivery':'prequeued entry -> loopback SMTP sink final acknowledgement and QUIT',
                                          'unix_to_smtp':'Unix client submission -> queue-ID -> loopback SMTP sink acknowledgement and QUIT'}),
                  cases=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for boundary in report['method']['boundaries']:
        case = dict(name=boundary, status='pending', samples=[], warmup=None)
        report['cases'].append(case)
        try:
            for iteration in range(args.runs+1):
                with tempfile.TemporaryDirectory(prefix='mb-', dir='/tmp') as tmp:
                    root = Path(tmp); queue = root/'queue'
                    source = root/'message'; source.write_bytes(payload)
                    with m.Shell(binary) as server, m.Shell(binary) as client:
                        daemon = m.Daemon(server, root) if boundary in ['unix_enqueue', 'unix_to_smtp'] else None
                        durations = []
                        received = 0
                        ids = set()
                        for _ in range(args.messages):
                            args_submit = ['mail', 'submit', '-f', m.FROM]
                            args_submit += ['--socket', daemon.sock] if daemon else ['--direct', '--queue', queue]
                            submit_cmd = m.words(*args_submit, '--', *m.RCPTS)+' < '+m.words(source)
                            if boundary == 'smtp_delivery':
                                qid = client.command(submit_cmd).strip().decode()
                                m.check_entry(queue, qid, payload)
                            sink = m.Sink() if boundary in ['smtp_delivery', 'unix_to_smtp'] else None
                            start = time.perf_counter_ns()
                            if boundary != 'smtp_delivery':
                                qid = client.command(submit_cmd).strip().decode()
                            if sink:
                                output = m.deliver(client, queue, qid, sink)
                            elapsed = time.perf_counter_ns()-start
                            assert qid not in ids; ids.add(qid)
                            m.check_entry(queue, qid, payload)
                            if sink:
                                assert output == b''.join(f'delivered {r}\n'.encode() for r in m.RCPTS)
                                assert sink.received == expected
                                received += len(sink.received)
                            durations.append(elapsed/1e6)
                        if daemon:
                            daemon.stop()
                        assert len(list((queue/'active').iterdir())) == args.messages
                        sample = dict(messages=args.messages, input_bytes=args.messages*len(payload),
                                      delivered_messages=args.messages if received else 0,
                                      delivered_bytes=received, boundary_ms=sum(durations),
                                      latency_ms=durations, validation='exact envelope, queue IDs, queue headers/body; exact SMTP commands and unstuffed contents where delivered')
                        if iteration == 0:
                            case['warmup'] = sample
                        else:
                            case['samples'].append(sample)
            totals = [s['boundary_ms'] for s in case['samples']]
            latency = [v for s in case['samples'] for v in s['latency_ms']]
            case.update(status='ok', median_batch_ms=statistics.median(totals),
                        min_batch_ms=min(totals), max_batch_ms=max(totals),
                        median_latency_ms=statistics.median(latency),
                        p95_latency_ms=sorted(latency)[int(.95*(len(latency)-1))],
                        messages_per_second=args.messages*1000/statistics.median(totals),
                        input_bytes_per_second=args.messages*len(payload)*1000/statistics.median(totals),
                        delivered_bytes_per_second=(args.messages*len(expected)*1000/statistics.median(totals) if boundary in ['smtp_delivery','unix_to_smtp'] else None))
            print(boundary, case['status'], round(case['median_batch_ms'], 3), 'ms', flush=True)
        except BaseException as exc:
            case.update(status='failed', error=repr(exc))
            raise
        finally:
            args.output.write_text(json.dumps(report, indent=2)+'\n')
    assert all(c['status'] == 'ok' for c in report['cases'])


if __name__ == '__main__':
    main()
