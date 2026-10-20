#!/usr/bin/env python3
"""Matched private-file ext2 creation; run only through the campaign bench gate."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mkfs_contract', ROOT / 'tests/sol-mkfs.py')
contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
SIZE = 8 * 1024**2
COUNT = 8
REFERENCE_CONFIG = '[defaults]\n default_mntopts = ^acl,^user_xattr\n enable_periodic_fsck = 1\n[fs_types]\n small = {\n inode_ratio = 4096\n }\n'
OPTIONS = ['-b', '1024', '-m', '5', '-L', 'fixture']
REFERENCE_OPTIONS = ['-q', '-F', '-t', 'ext2', '-b', '1024', '-m', '5', '-L', 'fixture',
                     '-I', '128', '-N', '2048', '-g', '8192', '-O', 'none,dir_index,filetype,sparse_super',
                     '-E', 'lazy_itable_init=0,nodiscard']


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_reference(image):
    # Check allocation and creation semantics independently of timestamps/UUID,
    # backup-superblock clean-state conventions and inode allocator placement.
    with image.open('rb') as f:
        f.seek(1024); sb = f.read(1024)
        expected = {0:2048, 4:8192, 8:409, 12:7918, 16:2037, 20:1, 24:0,
                    32:8192, 40:2048, 76:1, 84:11, 92:32, 96:2, 100:1, 256:0}
        for off, n in expected.items(): assert contract.U32(sb, off) == n, (off, contract.U32(sb, off), n)
        assert contract.U16(sb, 56) == 0xef53 and contract.U16(sb, 88) == 128
        assert sb[120:136] == b'fixture'.ljust(16, b'\0')
        f.seek(2048); gd = f.read(32)
        assert contract.U16(gd, 12) == 7918 and contract.U16(gd, 14) == 2037 and contract.U16(gd, 16) == 2
        f.seek(contract.U32(gd, 8)*1024 + 128); inode = f.read(128)
        assert contract.U16(inode, 0) == 0o40755 and contract.U16(inode, 26) == 3
        f.seek(contract.U32(gd, 8)*1024 + 10*128); inode = f.read(128)
        assert contract.U16(inode, 0) == 0o40700 and contract.U32(inode, 4) == 12288
        f.seek(contract.U32(gd, 0)*1024); bitmap = f.read(1024)
        assert sum(8 - b.bit_count() for b in bitmap) == 7918
    return contract.references(image, 1024, b'fixture')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', default='out/bash-sol-mkfs')
    ap.add_argument('--output', required=True)
    ap.add_argument('--runs', type=int, default=7)
    args = ap.parse_args()
    assert args.runs >= 7
    binary = str(Path(args.binary).resolve())
    ref = shutil.which('mke2fs') or '/sbin/mke2fs'
    affinity = sorted(os.sched_getaffinity(0))
    assert len(affinity) == 1, 'bench gate must fix affinity'
    output = Path(args.output).resolve()
    report = dict(status='running', created_utc=datetime.now(timezone.utc).isoformat(), workload='eight 8 MiB ext2 images, 1 KiB blocks, 128-byte inodes, 2048 inodes, 5% reserved',
        work_unit=dict(images=COUNT, image_bytes=SIZE, blocks_per_image=8192, options=OPTIONS,
                       reference_options=REFERENCE_OPTIONS, reference_config=REFERENCE_CONFIG, reset='fresh sparse zero file per image before timing; deletion outside timing',
                       fixture_sha256=hashlib.sha256(bytes(SIZE)).hexdigest()),
        environment=dict(platform=platform.platform(), cpu_affinity=affinity,
                         cpuinfo=Path('/proc/cpuinfo').read_text().split('model name',1)[-1].split('\n',1)[0],
                         python=platform.python_version(), kernel=platform.release()),
        provenance=dict(binary=binary, binary_sha256=sha(binary), source_sha256=sha(ROOT/'loadables/mkfs.c'),
                        harness_sha256=sha(__file__), reference=ref, reference_sha256=sha(ref),
                        source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                        source_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','--','loadables/mkfs.c'],cwd=ROOT)).hexdigest(),
                        binary_version=subprocess.check_output([binary,'--version'],text=True).splitlines()[0],
                        reference_version=subprocess.run([ref,'-V'],capture_output=True,text=True).stderr.strip()),
        samples_ns={'builtin':[], 'mke2fs':[]}, validation=[], profiles={})
    output.write_text(json.dumps(report, indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='sol-mkfs-bench-') as tmp:
        root=Path(tmp)
        config = root / 'mke2fs.conf'; config.write_text(REFERENCE_CONFIG)
        runenv = {**os.environ, 'MKE2FS_CONFIG':str(config)}
        def images(count):
            paths=[]
            for i in range(count):
                p=root/f'image-{i}'
                with p.open('wb') as f: f.truncate(SIZE)
                paths.append(contract.private_image(root,p))
            return paths
        def command(kind, paths):
            executable = 'mkfs' if kind == 'builtin' else shlex.quote(ref)
            options = OPTIONS if kind == 'builtin' else REFERENCE_OPTIONS
            script = 'PATH=; for image; do '+executable+' '+shlex.join(options)+' "$image" >/dev/null 2>&1 || exit; done; printf "ok\\n"'
            return [binary,'--noprofile','--norc','-c',script,'_',*paths]
        def validate(kind, paths):
            refs=[]
            for p in paths:
                assert Path(p).stat().st_size == SIZE
                if kind == 'builtin': contract.layout(p,1024,b'fixture')
                else: validate_reference(Path(p))
                refs.append(contract.references(p,1024,b'fixture'))
            return dict(status='pass', kind=kind, images=len(paths), references=refs)
        # Untimed syscall work profiles, in the same benchmark resource gate.
        # The annotated fd paths distinguish image writes from shell diagnostics.
        for kind in ('builtin','mke2fs'):
            paths=images(1)
            trace=output.with_name(output.stem+'-'+kind+'-strace.log')
            p=subprocess.run(['strace','-f','-qq','-yy','-o',str(trace),'-e',
                              'trace=pwrite64,write,writev,fsync,fdatasync,ftruncate,fallocate,ioctl',*command(kind,paths)],capture_output=True,env=runenv)
            assert p.returncode == 0 and p.stdout == b'ok\n', (p.returncode,p.stdout,p.stderr)
            validate(kind,paths)
            lines=trace.read_text().splitlines()
            writes=[line for line in lines if re.search(r'\b(?:pwrite64|write|writev)\(',line) and '<'+paths[0]+'>' in line]
            values=[int(re.search(r'= (\d+)\s*$',line).group(1)) for line in writes]
            flushes=[line for line in lines if re.search(r'\b(?:fsync|fdatasync)\(',line) and '<'+paths[0]+'>' in line]
            assert writes and flushes and all('= 0' in line for line in flushes), (kind,writes,flushes)
            report['profiles'][kind]=dict(status='pass', image_write_calls=len(writes), image_written_bytes=sum(values),
                                         flush_calls=len(flushes), trace=str(trace), allocated_image_bytes=Path(paths[0]).stat().st_blocks*512,
                                         allocation_requests=[line for line in lines if 'fallocate(' in line or 'ftruncate(' in line])
            if kind == 'builtin':
                assert sum(values) == contract.layout(paths[0],1024,b'fixture')['written_bytes']
            for p in paths: Path(p).unlink()
        for round_no in range(-1,args.runs):
            for kind in (('builtin','mke2fs') if round_no % 2 else ('mke2fs','builtin')):
                paths=images(COUNT)
                start=time.perf_counter_ns()
                p=subprocess.run(command(kind,paths),capture_output=True,env=runenv)
                elapsed=time.perf_counter_ns()-start
                assert p.returncode == 0 and p.stdout == b'ok\n', (kind,p.returncode,p.stdout,p.stderr)
                verification=validate(kind,paths)
                report['validation'].append(dict(round=round_no,kind=kind,status=verification['status'],images=COUNT))
                if round_no >= 0: report['samples_ns'][kind].append(elapsed)
                for image in paths: Path(image).unlink()
        report['summary']={kind:dict(median_ns=statistics.median(vals),min_ns=min(vals),max_ns=max(vals),
                                     ns_per_image=statistics.median(vals)/COUNT) for kind,vals in report['samples_ns'].items()}
        report['kind']='compared'
        report['ratio_mke2fs_over_builtin']=report['summary']['mke2fs']['median_ns']/report['summary']['builtin']['median_ns']
        report['limitations']=['Regular-file creation only; no device/mount throughput or power-loss qualification.',
            'Equal image size, features, inode count, initial empty namespace, eager inode-table initialization and successful fsync; implementations issue different write counts, recorded in profiles.',
            'Timing includes one shell startup per eight images and mke2fs process creation per image; output checking and fixture reset are outside timing.',
            'The tools choose different UUIDs, timestamps, mount-count randomization and signed/unsigned directory-hash flags; no indexed directory is created. Initial fixture hashes match. UUIDs, hash seeds and timestamps are intentionally regenerated; raw output image hashes are not expected to match.']
        report['status']='pass'
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('status','summary','profiles','ratio_mke2fs_over_builtin')},indent=2))


if __name__ == '__main__': main()
