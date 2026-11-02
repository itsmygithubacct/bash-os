#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only qualification of the separate stage-1 kernel erasure control.

This receipt supplements executed client fixtures; it is never another
candidate behavior case. Missing or changed control evidence cannot close a
secret-storage requirement. No kernel, module, helper or candidate is executed.
"""
import ast
import hashlib
import json
from pathlib import Path
import re

REFERENCE = {'type': 'kernel-secret-erasure-v1', 'id': 'auth-stage1-kunit'}
REQUIREMENTS = {('auth/device-abi-and-fd-lifecycle', 'r4'),
                ('auth/pty-sealed-secret-lifecycle', 'r3'),
                ('auth/pty-sealed-secret-lifecycle', 'r4'),
                ('passwd/password_hash_updates', 'r5'),
                ('passwd/password_verification_lockout', 'r5')}
NAMES = ['append_binary_compare', 'length_distinguishes_zero_padding', 'seal_is_immutable',
         'append_fault_is_atomic_and_erased', 'capacity_and_overflow', 'export_preconditions_retain_secret',
         'export_once_erases_even_on_fault', 'empty_export_is_consumed', 'clear_erases_and_ids_do_not_repeat',
         'close_path_erases_every_state', 'bounded_slots_and_id_exhaustion', 'contexts_are_independent']
SOURCE_FILES = ['secrets.c', 'secrets.h', 'tests/kunit.c', 'tests/core_under_test.c', 'uapi/linux/bashos_auth.h']
CONFIG = ['CONFIG_KUNIT=y', 'CONFIG_BASHOS_AUTH_STAGE1_KUNIT_TEST=y', 'CONFIG_DEBUG_KERNEL=y',
          'CONFIG_PROVE_LOCKING=y', 'CONFIG_KASAN=y', 'CONFIG_KASAN_GENERIC=y', 'CONFIG_KASAN_INLINE=y']


def require(ok, message):
    if not ok:
        raise ValueError('kernel secret control: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned(spec):
    require(isinstance(spec, dict) and isinstance(spec.get('path'), str), 'artifact path missing')
    path = Path(spec['path'])
    require(path.is_absolute() and path.is_file(), 'artifact is not an absolute file path')
    data = path.read_bytes()
    require(sha(data) == spec.get('sha256'), 'artifact changed: ' + path.name)
    return data


def validate_log(text):
    # CPU mitigation advisories during boot are distinct from kernel test
    # diagnostics, which include a call trace or a CPU-tagged WARNING.
    require(not re.search(r'BUG:|KASAN:|held locks|Kernel panic|WARNING: CPU:|general protection fault|Call Trace:', text),
            'kernel diagnostic invalidates the erasure control')
    require(not re.search(r'(?mi)^\s*not ok\b|^\s*ok\b[^\n]*#\s*(?:SKIP|TODO)\b', text),
            'failed or skipped KTAP case')
    actual = re.findall(r'(?m)^\s+ok ([0-9]+) ([a-z_]+)\s*$', text)
    require(actual == [(str(i), name) for i, name in enumerate(NAMES, 1)], 'exact 12-case KTAP sequence differs')
    require(text.count('# Totals: pass:12 fail:0 skip:0 total:12') == 1 and
            text.count('ok 1 bashos-auth-stage1-secrets') == 1 and
            'reboot: Restarting system' in text, 'suite totals or requested shutdown missing')


def status(configuration, repo):
    spec = configuration.get('kernel_secret_control')
    if spec is None:
        return False
    require(isinstance(spec, dict) and spec.get('id') == REFERENCE['id'], 'unknown control receipt')
    proof = json.loads(pinned(spec['proof']))
    require(proof.get('schema') == 'bashos-auth-stage1-kunit-v1' and
            proof.get('source') == 'Debian linux-source-6.12 6.12.113-1', 'unsupported kernel control')
    require(proof.get('tests') == {'PASS': 12, 'FAIL': 0, 'SKIP': 0} and
            proof.get('qemu_exit') == 0 and proof.get('parser_exit') == 0 and
            proof.get('kasans_or_lockdep_errors') is False, 'kernel control did not complete cleanly')
    require(proof.get('rental_instance', '').isdigit(), 'rental provenance missing')
    artifacts = spec.get('artifacts')
    require(isinstance(artifacts, dict) and set(artifacts) == {'kernel', 'config', 'log', 'parser', 'module', 'device_test'},
            'kernel, module, device-control and execution artifacts required')
    data = {name: pinned(value) for name, value in artifacts.items()}
    require(proof.get('artifact_sha256') == {name: sha(value) for name, value in data.items()},
            'receipt does not bind every runtime artifact')
    validate_log(data['log'].decode())
    require('Testing complete. Ran 12 tests: passed: 12' in data['parser'].decode(), 'official KUnit parser did not pass')
    require(proof.get('config') == CONFIG and set(CONFIG) <= set(data['config'].decode().splitlines()),
            'requested KASAN/lockdep configuration missing')
    source = Path(repo) / 'kernel/bashos-auth'
    require(proof.get('source_sha256') == {name: sha((source / name).read_bytes()) for name in SOURCE_FILES},
            'tested storage or erasure-test source differs')
    module_sources = ['device.c', 'secrets.c', 'secrets.h', 'uapi/linux/bashos_auth.h']
    require(proof.get('module_source_sha256') == {name: sha((source / name).read_bytes()) for name in module_sources},
            'real-device module source differs')
    helper = Path(repo) / 'tests/parity-vm/helpers/auth-stage1-fixture.py'
    assignments = [node for node in ast.parse(helper.read_text()).body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'PINS' for t in node.targets)]
    require(len(assignments) == 1, 'client artifact pins missing')
    pins = ast.literal_eval(assignments[0].value)
    require(pins.get('auth-stage1.ko') == sha(data['module']) and
            pins.get('auth-stage1-device-test') == sha(data['device_test']),
            'client fixture uses different kernel/device-control artifacts')
    return True
