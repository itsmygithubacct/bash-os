#!/usr/bin/python3
"""Coordinator-launched native qualification inside an isolated disposable guest."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

HERE = Path(__file__).resolve().parent
RECEIPT = Path('/root/clamp-native-receipt-r2.json')


def save(report):
    temporary = RECEIPT.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    os.replace(temporary, RECEIPT)


def main():
    report = {'schema': 'clamp-native-r2', 'qualified': False, 'stages': []}
    if os.geteuid() != 0:
        return 125
    # Read-only identity check before even creating a receipt. Namespace failures
    # inside the identified VM can then be retained without host-side writes.
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        if (str(uuid.UUID(marker)) != marker
                or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU'
                or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != marker):
            return 125
    except (OSError, ValueError):
        return 125
    save(report)
    try:
        if len(sys.argv) != 6:
            raise RuntimeError('expected token, outer namespaces, payload/index/source hashes')
        token, outer, payload_sha, index_sha, source_sha = sys.argv[1:]
        index_bytes = (HERE / 'clamp-qualification-index-r2.json').read_bytes()
        if hashlib.sha256(index_bytes).hexdigest() != index_sha:
            raise RuntimeError('qualification index hash differs')
        index = json.loads(index_bytes)
        if index.get('schema') != 'clamp-qualification-source-r2' or index.get('source_manifest_sha256') != source_sha:
            raise RuntimeError('qualification source manifest differs')
        for name, digest in index['files'].items():
            path = HERE / name
            if (Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink()
                    or not path.is_file() or not path.resolve().is_relative_to(HERE)
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                raise RuntimeError('qualification source differs: ' + name)
        report['source_binding'] = {'payload_sha256': payload_sha, 'index_sha256': index_sha,
                                    'source_manifest_sha256': source_sha, 'files': index['files']}
        save(report)
        spec = importlib.util.spec_from_file_location('clamp_guest', HERE / 'guest-clamp-r2.py')
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        report['isolation'] = guest.require_guest(token)
        report['namespace_attestation'] = guest.attest_namespaces(token, json.loads(outer))
        guest.clamp_r2.attest_side(False)
        original = guest.clamp_r2.snapshot()
        report['original_sysctls'] = original
        save(report)
        for helper, args, uid, diagnostics in [
            ('clamp-profile-control-r2.py', [], 2000, ['clamp-profile-control.json']),
            ('clamp-runtime-devices-uclamp-observer-r1-r2.py', ['preflight'], 2000, ['uclamp-events.json', 'uclamp-before.json']),
            ('clamp-live-sysctl-r2.py', ['--preflight'], 0, ['clamp-live-control.json'])]:
            stage = {'helper': helper, 'state': 'started'}
            report['stages'].append(stage)
            save(report)
            def run():
                guest.clamp_r2.attest_side(uid == 0)
                root = guest.workspace({})
                result = guest.plain(['/usr/bin/python3', '-I', str(HERE / 'helpers' / helper), *args],
                                     guest.environment('reference'), root,
                                     {'timeout': 55, 'privilege': 'root' if uid == 0 else None})
                result['diagnostics'] = guest.diagnostics({'diagnostic_files': diagnostics})
                return result
            try:
                stage['result'] = guest.privileged(run) if uid == 0 else run()
                stage['after_sysctls'] = guest.clamp_r2.snapshot()
                result = stage['result']
                if (result['status'] != 0 or result.get('error') or result.get('harness_error')
                        or stage['after_sysctls'] != original):
                    raise RuntimeError('native control/cleanup incomplete: ' + helper)
                stage['state'] = 'completed'
            except BaseException as error:
                stage.update(state='incomplete', error=type(error).__name__ + ': ' + str(error))
                raise
            finally:
                save(report)
        report['qualified'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        save(report)
    return 0 if report['qualified'] else 125


if __name__ == '__main__':
    raise SystemExit(main())
