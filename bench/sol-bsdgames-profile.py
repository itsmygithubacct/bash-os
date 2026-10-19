#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Profile the actual filter, only through the campaign bench gate.

No compilation. Syscall traces are diagnostic, never throughput samples.
Every successful traced invocation must emit exact independently checked bytes.
Unavailable performance counters are recorded with their real exits and stderr.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--before', type=Path, required=True)
    ap.add_argument('--after', type=Path, required=True)
    ap.add_argument('--directory', type=Path, required=True)
    args = ap.parse_args()
    args.directory.mkdir()  # Refuse to overwrite an earlier profile.
    assert len(os.sched_getaffinity(0)) == 1
    env = {'PATH': '', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb'}
    data = ''.join(f'{i//3:08d} word\n' for i in range(120000)).encode()
    # Different algorithm from the production translation map.
    expected = bytes(c + 13 if 65 <= c <= 77 or 97 <= c <= 109 else
                     c - 13 if 78 <= c <= 90 or 110 <= c <= 122 else c for c in data)
    reference = subprocess.run(['/usr/bin/tr', 'A-Za-z', 'N-ZA-Mn-za-m'],
                               input=data, capture_output=True, env=env, check=True)
    assert reference.stdout == expected
    report = {'affinity': sorted(os.sched_getaffinity(0)), 'environment': env,
              'bytes_per_pass': len(data), 'passes': 3, 'fixture_sha256': sha(data),
              'expected_sha256': sha(expected), 'tools': {}, 'cases': []}
    for tool in ['strace', 'perf', 'objdump']:
        path = shutil.which(tool)
        report['tools'][tool] = {'path': path}
        if path:
            p = subprocess.run([path, '--version'], capture_output=True, text=True)
            report['tools'][tool].update(sha256=sha(Path(path).read_bytes()),
                version=(p.stdout or p.stderr).splitlines()[0], exit_code=p.returncode)
    report['perf_event_paranoid'] = Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='sol-bsdgames-profile-') as tmp:
        fixture = Path(tmp)/'input'
        fixture.write_bytes(data)
        for label, binary in [('before', args.before), ('after', args.after)]:
            binary = str(binary.resolve(strict=True))
            script = 'for ((i=0;i<3;i++)); do bsdgames rot13 < "$1" || exit; done'
            argv = [binary, '--noprofile', '--norc', '-c', script, '_', str(fixture)]
            for tool in ['strace', 'perf-hardware', 'perf-software']:
                stem = args.directory/f'{label}-{tool}'
                trace = stem.with_suffix('.txt')
                executable = report['tools']['strace' if tool == 'strace' else 'perf']['path']
                row = {'implementation': label, 'tool': tool, 'binary_sha256': sha(Path(binary).read_bytes())}
                if not executable:
                    row.update(status='unavailable', reason='executable absent')
                    report['cases'].append(row)
                    continue
                if tool == 'strace':
                    command = [executable, '-qq', '-e', 'trace=read,write', '-s', '0', '-o', str(trace), *argv]
                else:
                    events = 'cycles,instructions,branches,branch-misses' if tool == 'perf-hardware' else 'task-clock,cpu-clock'
                    command = [executable, 'stat', '-e', events, '-o', str(trace), '--', *argv]
                output = Path(tmp)/'output'
                with output.open('wb') as stream:
                    p = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, env=env, timeout=60)
                stem.with_suffix('.stderr').write_bytes(p.stderr)
                row.update(command=command, exit_code=p.returncode, report=str(trace), stderr=str(stem.with_suffix('.stderr')))
                if p.returncode == 0:
                    actual = output.read_bytes()
                    assert actual == expected*3, (label, tool, 'invalid traced bytes')
                    row.update(status='ok', validated_passes=3, output_sha256=sha(actual), sink='private regular file')
                    if tool == 'strace':
                        lines = trace.read_text().splitlines()
                        for operation, fd in [('read', 0), ('write', 1)]:
                            sizes = [int(m.group(1)) for line in lines
                                     if (m := re.match(rf'{operation}\({fd}, .*\)\s+= (\d+)$', line))]
                            row[operation] = {'calls': len(sizes), 'bytes': sum(sizes),
                                              'sizes': {str(n): sizes.count(n) for n in sorted(set(sizes))}}
                            assert sum(sizes) == len(data)*3, (label, operation, sizes)
                else:
                    row.update(status='unavailable' if tool.startswith('perf') else 'error')
                report['cases'].append(row)
                (args.directory/'profile.json').write_text(json.dumps(report, indent=2)+'\n')
            objdump = report['tools']['objdump']['path']
            if objdump:
                p = subprocess.run([objdump, '-d', '--disassemble=caesar_filter', binary],
                                   capture_output=True, check=True)
                (args.directory/f'{label}-assembly.txt').write_bytes(p.stdout)
    assert all(row['status'] == 'ok' for row in report['cases'] if row['tool'] == 'strace')
    (args.directory/'profile.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
