#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Count allocations, copies, record moves and writes per clip operation.

    bench/sol-clip-profile.py --binary BASH --probe LABEL=OUT/probe.sh ... \
        --output REPORT.json

Each OUT comes from tests/sol-clip-build-probe.sh (pass a clip.c path to
profile another revision). Counters cover only calls made by buf.c and
clip.c: allocation requests (not live heap), explicit memcpy bytes, memmove
bytes and write(2) calls. Every operation's result is validated byte for byte
against an oracle built from the fixture, after the counters are read.
Counts, not timings."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('solclip', HERE / 'sol-clip.py')
solclip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solclip)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--probe', action='append', required=True, help='LABEL=LOADER; repeatable')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    probes = dict(p.split('=', 1) for p in args.probe)
    with tempfile.TemporaryDirectory(prefix='sol-clip-profile-') as td:
        d = Path(td)
        fx = {'text': solclip.catalog_text(), 'large': solclip.large_text()}
        for k, v in fx.items():
            (d / k).write_bytes(v)
        L = {k: v.split(b'\n') for k, v in fx.items()}
        realize = 'buf insert-line "$B" 0 x; buf delete-line "$B" 0; buf clean "$B"\n'
        ops = []
        for name, k in (('text', 4000), ('text', 8062), ('large', 65536)):
            entry = L[name][:k]
            n = len(L[name])
            mid = n // 2
            col = len(L[name][mid]) // 2
            joined = lambda lines: b'\n'.join(lines)
            pre, tail = L[name][mid][:col], L[name][mid][col:]
            colpaste = L[name][:mid] + [pre + entry[0]] + entry[1:-1] + [entry[-1] + tail] + L[name][mid + 1:]
            ops += [
                (f'text-{name}-{k}', realize + f'clip copy-range "$C" "$B" 0 {k}',
                 'clip text "$C" -F 3 3>out', '', b''.join(x + b'\n' for x in entry)),
                (f'copy-paged-{name}-{k}', '', f'clip copy-range "$C" "$B" 0 {k}',
                 'clip text "$C" -F 3 3>out', b''.join(x + b'\n' for x in entry)),
                (f'copy-realized-{name}-{k}', realize, f'clip copy-range "$C" "$B" 0 {k}',
                 'clip text "$C" -F 3 3>out', b''.join(x + b'\n' for x in entry)),
                (f'paste-lines-mid-{name}-{k}', realize + f'clip copy-range "$C" "$B" 0 {k}',
                 f'clip paste "$C" "$B" {mid}', 'buf text "$B" -F 3 3>out',
                 joined(L[name][:mid] + entry + L[name][mid:])),
                (f'paste-col-mid-{name}-{k}', realize + f'clip copy-range "$C" "$B" 0 {k}',
                 f'clip paste "$C" "$B" {mid} {col}', 'buf text "$B" -F 3 3>out', joined(colpaste)),
                (f'cut-lines-front-{name}-{k}', realize, f'clip cut-range "$C" "$B" 0 {k}',
                 'buf text "$B" -F 3 3>out', joined(L[name][k:]) if k < n else b''),
            ]
        report = dict(method=__doc__.split('\n\n', 1)[1].strip(), fixtures={k: solclip.sha(v) for k, v in fx.items()},
                      binary_sha256=solclip.sha(args.binary.read_bytes()),
                      probes={k: dict(loader=v, so_sha256=solclip.sha(Path(v).with_name('probe.so').read_bytes()))
                              for k, v in probes.items()}, operations=[])
        bad = []
        for name, setup, op, check, want in ops:
            row = dict(operation=name, validated_bytes=len(want), results={})
            for label, loader in probes.items():
                script = (f'PATH=\nset -e\nenable -f {Path(loader).with_name("probe.so")} buf clip clipprobe\n'
                          f'buf new -h B; buf load "$B" {name.split("-")[-2]}; clip new -h C\n{setup}\n'
                          f'clipprobe reset\n{op}\nclipprobe stats\n{check}\n')
                p = subprocess.run([str(args.binary), '-c', script], cwd=d, capture_output=True, timeout=1800)
                out = (d / 'out').read_bytes() if (d / 'out').exists() else None
                ok = p.returncode == 0 and out == want
                stats = json.loads(p.stdout.splitlines()[0]) if ok else None
                row['results'][label] = dict(status='ok' if ok else 'invalid', counts=stats,
                                             stderr=p.stderr[-300:].decode('replace'))
                if not ok:
                    bad.append((name, label))
                (d / 'out').unlink(missing_ok=True)
            print(name, {k: (v['counts'] if v['counts'] else v['status']) for k, v in row['results'].items()}, flush=True)
            report['operations'].append(row)
        args.output.write_text(json.dumps(report, indent=1) + '\n')
        print('invalid:', bad)
        return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
