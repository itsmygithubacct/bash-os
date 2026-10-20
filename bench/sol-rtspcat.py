#!/usr/bin/env python3
"""Validated loopback API timings, with independent exact frame bytes.
Run only through the campaign bench gate. Builds are separate.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rtsp_fixture', ROOT / 'tests/sol-rtspcat-loopback.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sample(binary, frames, standalone):
    data, expected = fixture.good_stream(frames)
    server = fixture.Server(data)
    command = [str(binary), server.client_url, '-n', str(frames)] if standalone else [str(binary), '--noprofile', '--norc', '-c', 'PATH=; rtspcat ' + shlex.quote(server.client_url) + f' -n {frames}']
    start = time.perf_counter_ns()
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, 'PATH': ''})
    first = p.stdout.read(4)
    assert len(first) == 4, (first, p.stderr.read())
    size = int.from_bytes(first, 'big')
    first_body = p.stdout.read(size)
    first_ns = time.perf_counter_ns() - start
    # communicate() may skip bytes already buffered by read(); read this same
    # pipe to EOF, then wait, so every frame remains part of the oracle.
    rest = p.stdout.read()
    err = p.stderr.read()
    status = p.wait(timeout=10)
    end_ns = time.perf_counter_ns() - start
    server.finish()
    output = first + first_body + rest
    assert status == 0 and output == expected, (status, len(output), len(expected), err)
    assert server.methods == ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY', 'TEARDOWN'], server.methods
    return dict(status='pass', frames=frames, framed_bytes=len(output), annexb_bytes=len(output)-4*frames,
                elapsed_ns=end_ns, first_frame_ns=first_ns, output_sha256=hashlib.sha256(output).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--frames', default=1200, type=int)
    parser.add_argument('--runs', default=7, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert args.runs >= 7 and args.frames >= 3
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'pin to one CPU using the bench gate/taskset'
    binary = args.binary.resolve()
    warmup = sample(binary, args.frames, args.standalone)
    samples = [sample(binary, args.frames, args.standalone) for _ in range(args.runs)]
    data, expected = fixture.good_stream(args.frames)
    med = statistics.median(s['elapsed_ns'] for s in samples)
    report = dict(status='pass', kind='api', comparison=None,
                  method='owned IPv4 loopback RTSP/TCP; exact independent Annex-B framed byte oracle on every pass; shell startup + handshake + stream; one warmup then repeated fresh server/shell',
                  reset='new ephemeral loopback listener, deterministic sequence wrap and timestamps, fresh shell each pass, no external network',
                  binary=str(binary), binary_sha256=sha(binary),
                  source_sha256=sha(ROOT / 'loadables/rtspcat.c'),
                  fixture_sha256=sha(ROOT / 'tests/sol-rtspcat-loopback.py'),
                  driver_sha256=sha(__file__), wire_sha256=hashlib.sha256(data).hexdigest(), expected_sha256=hashlib.sha256(expected).hexdigest(),
                  options=['-n', str(args.frames)], frames_per_pass=args.frames, framed_bytes_per_pass=len(expected),
                  environment=dict(cpu_affinity=affinity, platform=platform.platform(), python=sys.version,
                                   compiler=subprocess.run(['cc', '--version'], text=True, capture_output=True).stdout.splitlines()[0],
                                   binary_version=subprocess.run([str(binary), '--version'], text=True, capture_output=True).stdout.splitlines()[:1] if not args.standalone else ['standalone C implementation'],
                                   cpu_model=next((l.split(':', 1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')), 'unknown')),
                  warmup=warmup, samples=samples,
                  summary=dict(median_elapsed_ms=med/1e6, min_elapsed_ms=min(s['elapsed_ns'] for s in samples)/1e6,
                               max_elapsed_ms=max(s['elapsed_ns'] for s in samples)/1e6,
                               median_first_frame_ms=statistics.median(s['first_frame_ns'] for s in samples)/1e6,
                               frames_per_second=args.frames*1e9/med, framed_bytes_per_second=len(expected)*1e9/med),
                  limitations=['API end-to-end timing includes Python server, scheduler and shell startup; no decoder or real camera qualification.', 'No external reference with equivalent framing/auth/loss policy was measured; no speedup ratio.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary'], indent=2))


if __name__ == '__main__':
    main()
