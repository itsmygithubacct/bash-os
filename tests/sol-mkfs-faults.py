#!/usr/bin/env python3
"""Fault injection in production mkfs; compile modules separately under build gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('mkfs_contract', Path(__file__).with_name('sol-mkfs.py'))
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='out/bash-sol-mkfs')
    ap.add_argument('--module', required=True)
    ap.add_argument('--asan-lib')
    ap.add_argument('--report', required=True)
    args = ap.parse_args()
    binary, module = map(lambda p: str(Path(p).resolve()), (args.binary, args.module))
    results = []
    with tempfile.TemporaryDirectory(prefix='sol-mkfs-faults-') as tmp:
        root = Path(tmp); image = root / 'image'
        env = {**os.environ, 'MKFS_FIXTURE_ROOT': tmp}
        if args.asan_lib:
            env.update(LD_PRELOAD=args.asan_lib, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        def reset():
            with image.open('wb') as f: f.truncate(60 * 1024)
            contract.private_image(root, image)
        def run(mode, nth=1, expected=1, extra=()):
            reset()
            script = ('enable -f "$1" mkfs_probe || exit; PATH=; before=(/proc/self/fd/*); '
                      'mkfs_probe "$2" "$3" "$4" "${@:5}"; rc=$?; '
                      '[[ $rc == "$EXPECTED" ]] || exit 90; '
                      'after=(/proc/self/fd/*); [[ ${#before[@]} == ${#after[@]} ]] || exit 91; '
                      'mkfs_probe none 0 "$4" >/dev/null || exit 92; echo survived')
            p = subprocess.run([binary, '-c', script, '_', module, mode, str(nth), str(image), *extra],
                               capture_output=True, timeout=20, env={**env, 'EXPECTED': str(expected)})
            assert p.returncode == 0, (mode, nth, p.returncode, p.stdout, p.stderr)
            lines = p.stdout.splitlines()
            assert len(lines) == 2 and lines[1] == b'survived', p.stdout
            stats = json.loads(lines[0]); assert stats['status'] == expected
            assert stats['live_fds'] == stats['live_allocations'] == 0
            contract.layout(image, 1024)
            results.append(dict(mode=mode, nth=nth, stats=stats))
            return stats
        good = run('none', expected=0)
        assert good['written_bytes'] == contract.layout(image, 1024)['written_bytes']
        for nth in range(1, good['write_calls'] + 1):
            run('write', nth)
            run('write-zero', nth)
            run('write-short', nth, 0)
            run('write-eintr', nth, 0)
        for nth in range(1, 4): run('alloc', nth)
        for mode in ('open', 'fstat', 'random-open', 'read', 'read-zero', 'fsync', 'fsync-einval', 'close', 'ioctl'):
            stats = run(mode)
            if mode in ('alloc', 'open', 'fstat', 'random-open', 'read', 'read-zero', 'ioctl'):
                assert stats['written_bytes'] == 0
        for nth in (1, 2):
            for mode in ('read-eintr', 'read-short'): run(mode, nth, 0)
        for bs in (1024, 2048, 4096):
            with image.open('wb') as f: f.truncate(8 * 1024**2)
            contract.private_image(root, image)
            p = subprocess.run([binary, '-c', 'enable -f "$1" mkfs_probe; PATH=; mkfs_probe block 1 "$2" -b "$3"',
                                '_', module, str(image), str(bs)], capture_output=True, timeout=20, env=env)
            assert p.returncode == 0, (p.stdout, p.stderr)
            stats = json.loads(p.stdout)
            work = contract.layout(image, bs)
            assert stats['ioctls'] == 1 and stats['written_bytes'] == work['written_bytes']
            assert stats['live_fds'] == stats['live_allocations'] == 0
            results.append(dict(mode='block', block_size=bs, stats=stats,
                                references=contract.references(image, bs, b'')))
        p = subprocess.run([binary, '-c', 'enable -f "$1" mkfs_probe; PATH=; mkfs_probe helpers 0 "$2"',
                            '_', module, str(image)], capture_output=True, timeout=20, env=env)
        assert p.returncode == 0, (p.stdout, p.stderr)
        # Every fault module open rejects host paths before issuing a real open.
        # This operand intentionally never reaches the kernel.
        p = subprocess.run([binary, '-c', 'enable -f "$1" mkfs_probe; PATH=; mkfs_probe none 0 /dev/fixture-forbidden',
                            '_', module], capture_output=True, timeout=20, env=env)
        assert p.returncode == 1 and json.loads(p.stdout)['written_bytes'] == 0
    Path(args.report).write_text(json.dumps(dict(status='pass', cases=results,
        safety='closed production-call boundary, private regular images only; simulated BLKGETSIZE64',
        binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        module_sha256=hashlib.sha256(Path(module).read_bytes()).hexdigest(),
        source_sha256=hashlib.sha256((Path(__file__).resolve().parents[1]/'loadables/mkfs.c').read_bytes()).hexdigest()), indent=2) + '\n')
    print(f'sol-mkfs-faults: {len(results)} production fault/recovery/block cases passed')


if __name__ == '__main__': main()
