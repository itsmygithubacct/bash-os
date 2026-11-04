#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sequential real-record gate; coordinator's attested disposable guest only."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from guest import clean_env, digest, entrypoint, guard, save


def archive_storage(path):
    """True for a path under an archive-only root named in BASH_OS_ARCHIVE_PATHS."""
    roots = [Path(entry).resolve() for entry in
             os.environ.get('BASH_OS_ARCHIVE_PATHS', '').split(':') if entry]
    return any(path == root or root in path.parents for root in roots)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('static_shell'); p.add_argument('dynamic_shell'); p.add_argument('output_directory')
    p.add_argument('--static-sha256', required=True); p.add_argument('--dynamic-sha256', required=True)
    p.add_argument('--kernel-manifest', required=True); p.add_argument('--kernel-manifest-sha256', required=True)
    p.add_argument('--oracle', choices=('raw-bytes', 'util-linux'), required=True)
    p.add_argument('--reference-dmesg', default='-'); p.add_argument('--reference-sha256')
    a = p.parse_args(); guard(root=True)
    out = Path(a.output_directory).resolve()
    if out.exists() or archive_storage(out):
        raise RuntimeError('requires a new active-storage output directory')
    # Reject an unreviewed/ordinary kernel before writing anything to its ring.
    if digest(a.kernel_manifest) != a.kernel_manifest_sha256:
        raise RuntimeError('kernel manifest hash mismatch')
    manifest = json.loads(Path(a.kernel_manifest).read_text())
    if manifest.get('source_deb_sha256') != '6ad4a0316ddefced87cef8cd9a25a268e0cdfe0a10adc5148401f49f90b336b5':
        raise RuntimeError('wrong kernel source profile')
    release = manifest.get('kernel_release', '')
    if (not re.fullmatch(r'6\.12\.113[-+][A-Za-z0-9_.+-]+', release) or
            release != os.uname().release or '+deb13' in release or
            release == '6.12.113-clamp-parity-r1'):
        raise RuntimeError('requires the separately reviewed large-record derivative')
    config_hash = manifest.get('config_sha256', '')
    image_hash = manifest.get('kernel_image_sha256') or manifest.get('files', {}).get('boot/vmlinuz-' + release, '')
    if (any(not re.fullmatch('[0-9a-f]{64}', h) for h in (config_hash, image_hash)) or
            digest('/boot/config-' + release) != config_hash or
            digest('/boot/vmlinuz-' + release) != image_hash or
            hashlib.sha256(gzip.decompress(Path('/proc/config.gz').read_bytes())).hexdigest() != config_hash):
        raise RuntimeError('kernel/config preflight differs before ring writes')
    if a.oracle == 'util-linux':
        if not a.reference_sha256 or digest(a.reference_dmesg) != a.reference_sha256:
            raise RuntimeError('reviewed modified-reference hash required')
    elif a.reference_dmesg != '-' or a.reference_sha256:
        raise RuntimeError('raw-byte oracle must not name a utility reference')
    for side in ('static', 'dynamic'):
        if digest(getattr(a, side + '_shell')) != getattr(a, side + '_sha256'):
            raise RuntimeError('candidate hash mismatch: ' + side)
        if getattr(a, side + '_sha256') in {
                '11e4edf30b60abeab3318fedd5a4052f783d2500576a934b295bca451e5b6308',
                '090c95cd49df3478967c0acb73534d425ed099ba0ef55e5522745d30fec0c039'}:
            raise RuntimeError('frozen release cannot be relabeled')
    source = Path(__file__).resolve().parent
    names = ('guest.py', 'kmsg-abi.py', 'kmsg-boundary-r3.py')
    source_hashes = {name: digest(source/name) for name in names}
    out.mkdir(mode=0o700)
    observations = []
    for size in (8191, 8192, 8193):
        seed = out/f'seed-{size}.json'; result = out/f'boundary-{size}.json'
        row = {'target_bytes': size, 'result': 'ERROR'}; observations.append(row)
        command = [sys.executable, str(source/'kmsg-abi.py'), str(seed), '--target', str(size)]
        try:
            r = subprocess.run(command, env=clean_env(), capture_output=True, timeout=30)
            row['seed_transport'] = {'status': r.returncode, 'stdout_hex': r.stdout.hex(), 'stderr_hex': r.stderr.hex()}
            observed = json.loads(seed.read_text()) if seed.exists() else {}
            if (r.returncode or r.stdout or r.stderr or observed.get('result') != 'OBSERVED' or
                    observed.get('target_record_size') != size or not observed.get('target_reached')):
                row['error'] = 'actual kernel target/control not established'; break
            command = [sys.executable, str(source/'kmsg-boundary-r3.py'), str(seed),
                       a.static_shell, a.dynamic_shell, a.reference_dmesg, str(result),
                       '--release', '0.1.4', '--oracle', a.oracle,
                       '--static-sha256', a.static_sha256, '--dynamic-sha256', a.dynamic_sha256,
                       '--kernel-manifest', a.kernel_manifest,
                       '--kernel-manifest-sha256', a.kernel_manifest_sha256]
            if a.reference_sha256:
                command += ['--reference-sha256', a.reference_sha256]
            r = subprocess.run(command, env=clean_env(), capture_output=True, timeout=220)
            row['boundary_transport'] = {'status': r.returncode, 'stdout_hex': r.stdout.hex(), 'stderr_hex': r.stderr.hex()}
            observed = json.loads(result.read_text()) if result.exists() else {}
            verdict = observed.get('result')
            if (verdict not in ('PASS','FAIL','ERROR') or r.stdout or r.stderr or
                    r.returncode != {'PASS':0,'FAIL':1,'ERROR':125}.get(verdict)):
                raise RuntimeError('incomplete/inconsistent boundary receipt')
            row.update(result=verdict, by_build=observed.get('by_build'),
                       seed_sha256=digest(seed), boundary_sha256=digest(result))
            if verdict == 'ERROR':
                break  # a broken prerequisite cannot establish later targets
        except Exception as exc:
            row['error'] = str(exc); break
    result = 'ERROR'
    if len(observations) == 3 and all(r['result'] != 'ERROR' for r in observations):
        result = 'PASS' if all(r['result'] == 'PASS' for r in observations) else 'FAIL'
    save(out/'gate.json', {'schema':1,'result':result,'scope':'reviewed 0.1.4 builds on the reviewed real large-record kernel',
                          'oracle':a.oracle,'kernel_manifest_sha256':a.kernel_manifest_sha256,
                          'source_sha256':source_hashes,'observations':observations,
                          'reached_candidate_failures_retained':any(r['result']=='FAIL' for r in observations)})
    return {'PASS':0,'FAIL':1,'ERROR':125}[result]


if __name__ == '__main__':
    entrypoint(main)
