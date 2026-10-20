#!/usr/bin/env python3
"""Call counts (not timings) from sol-wc-calls.c; invoke through the bench gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', action='append', required=True, help='LABEL=PATH')
    p.add_argument('--module', type=lambda p: str(Path(p).resolve()), required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = dict(method='LD_PRELOAD counts in real wc and shell; subtract a no-op shell/redirection control. No timing or external ratio.',
                  cpus=sorted(os.sched_getaffinity(0)), cases=[])
    with tempfile.TemporaryDirectory(prefix='sol-wc-profile-') as d:
        for kind, seed in [('ascii', b'alpha beta gamma\n'), ('mixed', 'alpha café 界 e\u0301\tomega\n'.encode())]:
            data = seed*(423000//len(seed))
            fixture = Path(d)/'input'
            fixture.write_bytes(data)
            for item in args.binary:
                label, binary = item.split('=', 1)
                binary = str(Path(binary).resolve())
                row = dict(label=label, fixture=kind, fixture_sha256=hashlib.sha256(data).hexdigest(),
                           bytes=len(data), characters=len(data.decode()), binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest())
                for command in [':', 'wc']:
                    env = {'PATH': '', 'LC_ALL': 'C.UTF-8', 'LD_PRELOAD': args.module}
                    proc = subprocess.run([binary, '--noprofile', '--norc', '-c', command+' -m < "$1"', '_', str(fixture)], env=env, capture_output=True)
                    assert proc.returncode == 0, proc
                    assert proc.stdout == (str(row['characters'])+'\n').encode() if command == 'wc' else proc.stdout == b''
                    row['control' if command == ':' else 'wc'] = json.loads(proc.stderr)
                row['delta'] = {k: row['wc'][k]-v for k, v in row['control'].items()}
                report['cases'].append(row)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
