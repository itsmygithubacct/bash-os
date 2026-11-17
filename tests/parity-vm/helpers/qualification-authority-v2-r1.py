#!/usr/bin/python3
"""Guest-only transport for the pinned authority qualification packets.

The case supplies authority-inputs.json; every other input arrives through the
reference directory and is bound by SHA-256 through the pinned receipt. The
packet driver loads and unloads the modules itself. This transport adds the
checks that must not depend on the driver: the endpoint that the receipt
names, the exact control inventory, an independent kernel-log and taint
comparison, and the absence of any authority module or node before and after.
"""
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
CANDIDATE = Path('/opt/bashos-parity/candidate')
ENDPOINTS = ('production', 'qualification')
KERNEL_TERMS = (b'warning:', b'bug:', b'kasan:', b'kcsan:', b'ubsan:', b'held lock', b'oops:',
                b'possible recursive locking', b'inconsistent lock state', b'general protection fault',
                b'info: task ', b'panic:', b'call trace:', b'rcu: info:')
# Loading an out-of-tree, unsigned module sets these two taint bits; any other
# new bit (warning, oops, lockup, bad page, ...) is a kernel diagnostic.
MODULE_TAINT = (1 << 12) | (1 << 13)
PART_BYTES, PART_LIMIT = 400 * 1024, 8


def require(value, reason):
    if not value: raise RuntimeError(reason)


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference(name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, 'invalid reference path')
    return REFERENCES / path


def member(directory, name):
    require(Path(name).name == name and name not in ('', '.', '..'), 'nonlocal receipt member')
    path = directory / name; info = path.lstat()
    require(path.is_file() and not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
            'unprotected receipt member: ' + name)
    return path


def receipt_inputs(path, pin):
    require(path.is_file() and not path.is_symlink() and sha(path) == pin, 'receipt differs')
    value = json.loads(path.read_text())
    require(value['schema'] == 1 and isinstance(value['files'], dict) and value['files'], 'receipt schema differs')
    inputs = {str(path): pin}
    for name, entry in value['files'].items():
        artifact = member(path.parent, name)
        require(artifact.stat().st_size == entry['bytes'] and sha(artifact) == entry['sha256'],
                'receipt artifact differs: ' + name)
        inputs[str(artifact)] = entry['sha256']
    return value, inputs


def build_chain(path, value, inputs):
    """Bind every module and native program to the build tool's own receipt."""
    chain = value['build']
    build = member(path.parent, chain['receipt'])
    require(sha(build) == chain['sha256'], 'build tool receipt differs')
    tool = json.loads(build.read_text())
    require(tool['schema'] == 1 and tool['kind'] == 'bashos-authority-build' and
            tool['behavior_executed'] is False and tool['kernel_release'] == value['kernel_release'] and
            tool['source_manifest_sha256'] == chain['source_manifest_sha256'], 'build tool receipt contract differs')
    inputs[str(build)] = chain['sha256']
    built = sorted(name for name in value['files'] if name in tool['files'])
    for name in built:
        require(value['files'][name] == tool['files'][name], 'artifact is not the build tool output: ' + name)
    outside = sorted(set(value['files']) - set(built))
    require(sorted(chain['staged']) == outside, 'receipt lists an artifact the staging step did not declare')
    # Only interpreted drivers and the two pinned distribution libraries may
    # come from outside the build; no module or native program may.
    require(all(name.endswith(('.py', '.so.1', '.so.2', '.json')) for name in outside) and
            not any(name.endswith('.ko') for name in outside), 'native artifact outside the build receipt')
    return {'built': built, 'staged': outside, 'tool_receipt_sha256': chain['sha256'],
            'source_manifest_sha256': tool['source_manifest_sha256'], 'qualification_build': tool['qualification']}


def endpoint_contract(value, endpoint):
    require(endpoint in ENDPOINTS and value.get('endpoint') == endpoint, 'receipt names a different endpoint')
    modules = sorted(name for name in value['files'] if name.endswith('.ko'))
    test_modules = [name for name in modules if name.endswith('_test.ko')]
    if endpoint == 'production':
        require(modules and not test_modules, 'production receipt carries a test module')
        require(value.get('consumer_route') in ('default', 'explicit'), 'production receipt lacks the consumer route')
    else:
        require(test_modules, 'qualification receipt carries no test module')
    return modules


def authority_state():
    modules = sorted(path.name for path in Path('/sys/module').iterdir() if path.name.startswith('bashos_'))
    nodes = sorted(path.name for path in Path('/dev').iterdir() if path.name.startswith('bashos-'))
    return {'modules': modules, 'nodes': nodes, 'taint': int(Path('/proc/sys/kernel/tainted').read_text())}


def kernel_log():
    result = subprocess.run(['/usr/bin/dmesg', '--raw'], capture_output=True, timeout=30)
    require(result.returncode == 0, 'kernel log unavailable')
    return result.stdout


def retain(output, transport):
    (PRIVATE_HOME / 'authority-transport.json').write_text(json.dumps(transport, indent=2) + '\n')
    for name in ('report.json', 'dmesg-delta.txt'):
        source = output / name
        if source.is_file() and not source.is_symlink() and source.stat().st_size <= 256 * 1024:
            shutil.copyfile(source, PRIVATE_HOME / ('authority-' + name))
    archive = PRIVATE_HOME / 'authority-all.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        stream.add(PRIVATE_HOME / 'authority-transport.json', arcname='transport.json', recursive=False)
        if output.is_dir():
            for path in sorted(output.rglob('*')):
                require(not path.is_symlink(), 'diagnostic symlink refused')
                if path.is_file(): stream.add(path, arcname='results/' + str(path.relative_to(output)), recursive=False)
    data = archive.read_bytes(); archive.unlink()
    parts = [data[offset:offset + PART_BYTES] for offset in range(0, len(data), PART_BYTES)]
    require(len(parts) <= PART_LIMIT, 'complete diagnostics exceed capacity')
    for index, part in enumerate(parts):
        (PRIVATE_HOME / ('authority-all.tar.gz.%d' % index)).write_bytes(part)
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'parts': len(parts)}


def main():
    require(__debug__ and os.geteuid() == 0 and Path.cwd() == Path('/tmp/parity-case'), 'guest fixture context differs')
    spec = json.loads(Path('authority-inputs.json').read_text())
    require(set(spec) <= {'receipt', 'receipt_sha256', 'driver', 'driver_sha256', 'endpoint', 'expected_controls',
                          'control_ids_sha256', 'not_run', 'candidate_argument', 'observer_receipt',
                          'observer_receipt_sha256'}, 'unknown transport input')
    token = Path('/etc/bashos-parity-vm').read_text().strip()
    receipt, driver = reference(spec['receipt']), reference(spec['driver'])
    require(sha(receipt) == spec['receipt_sha256'] and sha(driver) == spec['driver_sha256'], 'input pin differs')
    candidate_pin = sha(CANDIDATE)
    output = PRIVATE_HOME / 'authority-results'
    command = ['/usr/bin/python3', '-B', str(driver), '--receipt', str(receipt),
               '--receipt-sha256', spec['receipt_sha256'], '--expected-uuid', token, '--output', str(output)]
    if spec.get('candidate_argument', True):
        command += ['--bash', str(CANDIDATE), '--bash-sha256', candidate_pin]
    value, inputs_before = receipt_inputs(receipt, spec['receipt_sha256'])
    require(driver.parent == receipt.parent or 'observer_receipt' in spec, 'driver is outside the pinned receipt directory')
    modules = endpoint_contract(value, spec['endpoint'])
    chain = build_chain(receipt, value, inputs_before)
    inputs_before.update({str(CANDIDATE): candidate_pin, str(driver): spec['driver_sha256']})
    if 'observer_receipt' in spec:
        observer = reference(spec['observer_receipt'])
        addon, addon_inputs = receipt_inputs(observer, spec['observer_receipt_sha256'])
        require(driver.parent == observer.parent and addon.get('endpoint') == spec['endpoint'] and
                addon['base_receipt_sha256'] == spec['receipt_sha256'], 'observer receipt chain differs')
        build_chain(observer, addon, addon_inputs)
        inputs_before.update(addon_inputs)
        command += ['--observer-receipt', str(observer), '--observer-receipt-sha256', spec['observer_receipt_sha256']]
    require(driver.name in value['files'] or 'observer_receipt' in spec, 'driver is not a receipt member')
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(PRIVATE_HOME),
           'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    transport = {'status': 125, 'stdout_hex': '', 'stderr_hex': '', 'uuid': token, 'endpoint': spec['endpoint'],
                 'modules': modules, 'build_chain': chain, 'candidate_sha256': candidate_pin,
                 'receipt_sha256': spec['receipt_sha256'], 'driver_sha256': spec['driver_sha256'],
                 'command': command, 'timed_out': False, 'input_sha256_before': inputs_before}
    state_before = authority_state(); log_before = kernel_log()
    transport['authority_state_before'] = state_before
    require(not state_before['modules'] and not state_before['nodes'], 'authority module or node present before the packet')
    try:
        result = subprocess.run(command, env=env, capture_output=True, timeout=600)
        transport.update(status=result.returncode, stdout_hex=result.stdout.hex(), stderr_hex=result.stderr.hex())
    except subprocess.TimeoutExpired as error:
        transport.update(timed_out=True, stdout_hex=(error.stdout or b'').hex(), stderr_hex=(error.stderr or b'').hex())
    except Exception as error:
        transport['setup_error'] = repr(error)
    finally:
        try:
            transport['input_sha256_after'] = {name: sha(name) for name in inputs_before}
            transport['inputs_unchanged'] = transport['input_sha256_after'] == inputs_before
        except Exception as error:
            transport['inputs_unchanged'] = False
            transport['input_readback_error'] = repr(error)
        try:
            state_after = authority_state(); log_after = kernel_log()
            delta = log_after[len(log_before):] if log_after.startswith(log_before) else None
            found = sorted({term.decode() for term in KERNEL_TERMS if delta is not None and term in delta.lower()})
            transport.update(authority_state_after=state_after, kernel_log_continuous=delta is not None,
                             kernel_log_delta_bytes=None if delta is None else len(delta),
                             kernel_log_delta_sha256=None if delta is None else hashlib.sha256(delta).hexdigest(),
                             kernel_diagnostic_terms=found,
                             new_taint=state_after['taint'] & ~state_before['taint'] & ~MODULE_TAINT)
            if delta is not None: (PRIVATE_HOME / 'authority-kernel-delta.txt').write_bytes(delta[-256 * 1024:])
        except Exception as error:
            transport['kernel_state_error'] = repr(error)
        # Preserve diagnostics even when the driver timed out or failed. Any
        # remaining guest resource then belongs to the controller's ERROR
        # cleanup; absence of a complete cleanup report can never pass here.
        transport['archive'] = retain(output, transport)
    require(not transport['timed_out'] and 'setup_error' not in transport, 'incomplete driver execution; raw data retained')
    require(transport['inputs_unchanged'] and sha(CANDIDATE) == candidate_pin, 'pinned inputs changed; raw data retained')
    require('kernel_state_error' not in transport and transport['kernel_log_continuous'],
            'kernel log lost or wrapped; raw data retained')
    require(not transport['kernel_diagnostic_terms'] and not transport['new_taint'],
            'new kernel warning or taint; raw data retained')
    after = transport['authority_state_after']
    require(not after['modules'] and not after['nodes'], 'authority module or node left behind; raw data retained')
    report = json.loads((output / 'report.json').read_text()) if (output / 'report.json').is_file() else {}
    status = report.get('status', 'ERROR')
    if status != 'PASS':
        print(status if status in ('FAIL', 'ERROR') else 'ERROR')
        return 1 if status == 'FAIL' else 125
    require(transport['status'] == 0 and not transport['stderr_hex'], 'PASS transport differs')
    require(json.loads(bytes.fromhex(transport['stdout_hex']))['status'] == 'PASS', 'PASS summary differs')
    rows = report['cases']; ids = [row['id'] for row in rows]
    require(len(rows) == spec['expected_controls'] == len(set(ids)) and all(row['status'] == 'PASS' for row in rows),
            'exact control matrix incomplete')
    require(hashlib.sha256(('\n'.join(ids) + '\n').encode()).hexdigest() == spec['control_ids_sha256'],
            'control inventory differs from the pinned inventory')
    require(report.get('endpoint') == spec['endpoint'] and
            report.get('controls_not_run_on_this_endpoint', []) == spec.get('not_run', []),
            'driver ran a different endpoint or omitted a different control set')
    require(report.get('receipt_sha256', spec['receipt_sha256']) == spec['receipt_sha256'] and
            report.get('bash_sha256', candidate_pin) == candidate_pin, 'report names different inputs')
    require(not report.get('cleanup_or_kernel_error') and not report.get('secondary_failures') and
            report.get('cleanup_status', 'PASS') == 'PASS' and report.get('kernel_status', 'PASS') == 'PASS',
            'cleanup/kernel error')
    if 'observer_receipt' in spec:
        require(report.get('ancestor_broker_cleanup', {}).get('status') == 'CLEAN' and
                not report.get('broker_cleanup_error'), 'ancestor broker cleanup incomplete')
    print('PASS endpoint=%s controls=%d' % (spec['endpoint'], len(rows)))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error: print(repr(error), file=sys.stderr); raise SystemExit(125)
