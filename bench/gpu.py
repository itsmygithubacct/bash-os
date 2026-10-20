#!/usr/bin/env python3
"""Validated application frames against a PTY protocol peer.
Run through the campaign bench gate; compile native fixtures separately through
the build gate. No external ratios: the Python peer contributes to latency.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gpu_frames', ROOT/'tests/sol-gpu-frames.py')
frames = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frames)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def distribution(values):
    ordered = sorted(values)
    return dict(samples=values, minimum=min(values), median=statistics.median(values),
                p95=ordered[min(len(ordered)-1, int(len(ordered)*.95))], maximum=max(values))


def driver(device, fixture):
    if fixture:
        return dict(kind='injected ABI model', path=str(Path(fixture).resolve()), sha256=sha(fixture),
                    qualification='host fixture only; no kernel DRM or hardware execution')
    if not device:
        return dict(kind='unavailable', qualification='native cases not measured')
    node = Path(device).resolve()
    stat = node.stat()
    sysfs = Path(f'/sys/dev/char/{os.major(stat.st_rdev)}:{os.minor(stat.st_rdev)}/device')
    result = dict(kind='native render node', node=str(node),
                  driver=str((sysfs/'driver').resolve()), qualification='available host device; intended-device qualification unspecified')
    for item in ('vendor','device','driver/module/version'):
        path = sysfs/item
        if path.is_file(): result[item] = path.read_text().strip()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', nargs='?', default=str(ROOT/'out/bash'))
    parser.add_argument('--device')
    parser.add_argument('--driver-fixture')
    parser.add_argument('--runs', type=int, default=7)
    parser.add_argument('--frames', type=int, default=frames.FRAMES)
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--only', help='Comma-separated frame case names')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('refusing to overwrite a raw report; choose a new --output path')
    if args.runs < 7 or args.frames < 2: parser.error('require at least seven samples and two frames')
    if args.driver_fixture and not args.device: parser.error('--driver-fixture requires an explicit private --device file')
    if args.cpu is not None: os.sched_setaffinity(0, {args.cpu})
    binary = Path(args.binary).resolve()
    sources = ['loadables/gpu.c','loadables/common/gpu-native.h',
               'loadables/_soft_raster/soft_raster.c','loadables/_soft_raster/soft_raster.h',
               'tests/gpu-smoke.py','tests/sol-gpu-frames.py','tests/sol-gpu-driver.c','tests/sol-gpu-build-fixture.sh','bench/gpu.py']
    report = dict(schema=1, kind='api',
                  qualification='host fixture timings include Python protocol replay; no terminal display latency or external ratio',
                  utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                  binary_sha256=sha(binary), binary=str(binary),
                  runtime_module=({'path':os.environ['GPU_MODULE'], 'sha256':sha(os.environ['GPU_MODULE'])} if os.environ.get('GPU_MODULE') else None),
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  source_sha256={p:sha(ROOT/p) for p in sources},
                  binary_version=subprocess.check_output([str(binary),'--version'],text=True).splitlines()[0],
                  compiler_version=subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
                  python=platform.python_version(), platform=platform.platform(),
                  cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                  load_average_start=os.getloadavg(),
                  affinity=sorted(os.sched_getaffinity(0)), driver=driver(args.device,args.driver_fixture),
                  environment={k:os.environ.get(k) for k in ('LD_LIBRARY_PATH','LD_PRELOAD','GPU_MODULE','GPU_ASAN_LIB','LIBGL_ALWAYS_SOFTWARE','MESA_LOADER_DRIVER_OVERRIDE','GBM_BACKEND','__EGL_VENDOR_LIBRARY_FILENAMES')},
                  options=dict(runs=args.runs, frames=args.frames, device=args.device, driver_fixture=args.driver_fixture),
                  work_unit=f'{args.frames} updates after one initial 640x360 frame per fresh shell; resize alternates 656x368 and 640x360',
                  reset='new shell, private PTY, session directory and empty private shader cache per warmup/sample; empty PATH in shell; independent peer validates and acknowledges each complete frame over an inherited pipe before the next update',
                  cases=[], unavailable=[])
    available = frames.cases(bool(args.device))
    selected = args.only.split(',') if args.only else available
    if any(name not in available for name in selected): parser.error('unknown or unavailable case in --only')
    if not args.device:
        report['unavailable'].append('Native shader/DMA-BUF driver cases: no --device supplied')
    for name in selected:
        item = dict(name=name, status='failed', samples=[])
        report['cases'].append(item)
        try:
            warmup = frames.execute(binary,name,frames=args.frames,device=args.device,fixture=args.driver_fixture)
            item['warmup'] = {k:v for k,v in warmup.items() if k not in ('frame_latency_ms','update_ms','present_ms','peer_completion_ms','host_peer_batch_ms','setup_and_first_frame_ms')}
            for _ in range(args.runs):
                result = frames.execute(binary,name,frames=args.frames,device=args.device,fixture=args.driver_fixture,measure=True)
                # Every repeated sample has its own pixel/protocol/counter oracle.
                for field in ('expected_sha256','tty_normalized_bytes','protocol_normalized_sha256','graphics_libraries','inline_rgba_bytes','shared_rgba_bytes','exported_pixel_bytes','terminal_counts','renderer'):
                    assert result[field] == warmup[field], (field, result[field], warmup[field])
                if item['samples']: assert result['script_sha256'] == item['samples'][0]['script_sha256']
                item['samples'].append(result)
            latencies = [v for sample in item['samples'] for v in sample['frame_latency_ms']]
            item.update(status='ok', frame_latency_ms=distribution(latencies),
                        tty_bytes=distribution([sample['tty_bytes'] for sample in item['samples']]),
                        update_ms=distribution([v for sample in item['samples'] for v in sample['update_ms']]),
                        present_ms=distribution([v for sample in item['samples'] for v in sample['present_ms']]),
                        peer_completion_ms=distribution([v for sample in item['samples'] for v in sample['peer_completion_ms']]),
                        host_peer_batch_ms=distribution([s['host_peer_batch_ms'] for s in item['samples']]),
                        setup_and_first_frame_ms=distribution([s['setup_and_first_frame_ms'] for s in item['samples']]),
                        shell_peak_rss_kib=distribution([s['shell_peak_rss_kib'] for s in item['samples']]))
        except Exception:
            item['error'] = traceback.format_exc()
            # Failed cases carry diagnostic work/counters, never latency summaries.
            for sample in item['samples']:
                sample.pop('frame_latency_ms',None); sample.pop('host_peer_batch_ms',None)
                sample.pop('setup_and_first_frame_ms',None); sample.pop('peer_completion_ms',None)
                sample.pop('update_ms',None); sample.pop('present_ms',None)
        report['load_average_end'] = os.getloadavg()
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(name, item['status'], flush=True)
    return int(any(c['status'] != 'ok' for c in report['cases']))


if __name__ == '__main__':
    raise SystemExit(main())
