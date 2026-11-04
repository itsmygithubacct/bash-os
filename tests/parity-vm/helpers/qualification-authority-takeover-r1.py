#!/usr/bin/python3
"""Guest-only transport for pinned authority and ancestor-observer controls."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

PRIVATE_HOME = Path('/tmp/parity-home')
REFERENCES = Path('/opt/bashos-parity/reference-data')


def require(value, reason):
    if not value: raise RuntimeError(reason)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, 'invalid reference path')
    return REFERENCES / path


def receipt_inputs(path, pin):
    require(path.is_file() and not path.is_symlink() and sha(path) == pin, 'receipt differs')
    value = json.loads(path.read_text())
    require(value['schema'] == 1, 'receipt schema differs')
    inputs = {str(path): pin}
    for name, entry in value['files'].items():
        require(Path(name).name == name and name not in ('', '.', '..'), 'nonlocal receipt member')
        artifact = path.parent / name
        require(artifact.is_file() and not artifact.is_symlink() and
                artifact.stat().st_size == entry['bytes'] and sha(artifact) == entry['sha256'],
                'native artifact differs: ' + name)
        inputs[str(artifact)] = entry['sha256']
    return inputs


def main():
    require(__debug__ and os.geteuid() == 0 and Path.cwd() == Path('/tmp/parity-case'), 'guest fixture context differs')
    spec = json.loads(Path('authority-inputs.json').read_text())
    token = Path('/etc/bashos-parity-vm').read_text().strip()
    receipt, driver = reference(spec['receipt']), reference(spec['driver'])
    require(sha(receipt) == spec['receipt_sha256'] and sha(driver) == spec['driver_sha256'], 'input pin differs')
    candidate = Path('/opt/bashos-parity/candidate'); candidate_pin = sha(candidate)
    require(candidate_pin in spec['candidate_sha256'].values(), 'candidate pin differs')
    output = PRIVATE_HOME / 'authority-results'
    command = ['/usr/bin/python3', '-B', str(driver), '--receipt', str(receipt),
               '--receipt-sha256', spec['receipt_sha256'], '--expected-uuid', token,
               '--output', str(output), '--bash', str(candidate), '--bash-sha256', candidate_pin]
    inputs_before = receipt_inputs(receipt, spec['receipt_sha256'])
    inputs_before.update({str(candidate): candidate_pin, str(driver): spec['driver_sha256']})
    if 'observer_receipt' in spec:
        observer = reference(spec['observer_receipt'])
        inputs_before.update(receipt_inputs(observer, spec['observer_receipt_sha256']))
        command += ['--observer-receipt', str(observer),
                    '--observer-receipt-sha256', spec['observer_receipt_sha256']]
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(PRIVATE_HOME),
           'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    transport = {'status': 125, 'stdout_hex': '', 'stderr_hex': '', 'uuid': token,
                 'receipt_sha256': spec['receipt_sha256'], 'command': command, 'timed_out': False,
                 'input_sha256_before': inputs_before}
    try:
        result = subprocess.run(command, env=env, capture_output=True, timeout=600)
        transport.update(status=result.returncode, stdout_hex=result.stdout.hex(), stderr_hex=result.stderr.hex())
    except subprocess.TimeoutExpired as error:
        transport.update(timed_out=True, stdout_hex=(error.stdout or b'').hex(), stderr_hex=(error.stderr or b'').hex())
    except Exception as error:
        transport['setup_error'] = repr(error)
    finally:
        try:
            transport['input_sha256_after'] = {name: sha(Path(name)) for name in inputs_before}
            transport['inputs_unchanged'] = transport['input_sha256_after'] == inputs_before
        except Exception as error:
            transport['inputs_unchanged'] = False
            transport['input_readback_error'] = repr(error)
        # Preserve diagnostics even when the driver timed out or failed. Any
        # remaining guest resource then belongs to the controller's ERROR
        # cleanup; absence of a complete cleanup report can never pass here.
        (PRIVATE_HOME / 'authority-transport.json').write_text(json.dumps(transport, indent=2) + '\n')
        for name in ('report.json', 'commands.json', 'dmesg-before.txt', 'dmesg-after.txt', 'dmesg-delta.txt'):
            source = output / name
            if source.is_file() and not source.is_symlink(): shutil.copyfile(source, PRIVATE_HOME / ('authority-' + name))
        archive = PRIVATE_HOME / 'authority-all.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            if output.is_dir():
                for path in sorted(output.rglob('*')):
                    require(not path.is_symlink(), 'diagnostic symlink refused')
                    if path.is_file(): stream.add(path, arcname=str(path.relative_to(output)), recursive=False)
        require(archive.stat().st_size <= 1024 * 1024, 'complete diagnostics exceed capacity')
    require(not transport['timed_out'] and 'setup_error' not in transport, 'incomplete driver execution; raw data retained')
    require(transport['inputs_unchanged'], 'native/candidate inputs changed; raw data retained')
    require(sha(candidate) == candidate_pin and sha(receipt) == spec['receipt_sha256'] and sha(driver) == spec['driver_sha256'],
            'inputs changed during observation')
    report = json.loads((output / 'report.json').read_text()) if (output / 'report.json').is_file() else {}
    status = report.get('status', 'ERROR')
    if status == 'PASS':
        require(transport['status'] == 0 and not transport['stderr_hex'], 'PASS transport differs')
        require(json.loads(bytes.fromhex(transport['stdout_hex']))['status'] == 'PASS', 'PASS summary differs')
        require(len(report['cases']) == spec['expected_controls'] and all(row['status'] == 'PASS' for row in report['cases']),
                'exact control matrix incomplete')
        require(not report.get('cleanup_or_kernel_error'), 'cleanup/kernel error')
        if 'observer_receipt' in spec:
            require(report.get('ancestor_broker_cleanup', {}).get('status') == 'CLEAN' and
                    not report.get('broker_cleanup_error'), 'ancestor broker cleanup incomplete')
        print('PASS'); return 0
    print(status if status in ('FAIL', 'ERROR') else 'ERROR')
    return 1 if status == 'FAIL' else 125


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error: print(repr(error), file=sys.stderr); raise SystemExit(125)
