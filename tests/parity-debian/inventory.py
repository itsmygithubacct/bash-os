#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check catalog accounting, or audit installed tools inside the reference image."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'tests/parity-debian'
KINDS = {'cli', 'adapter', 'contract-only'}
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
MODULE = re.compile(r'[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*\Z')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_list(path):
    names = [line.strip() for line in path.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    if any(not PACKAGE.fullmatch(name) for name in names):
        raise ValueError('packages.list must contain one unversioned Debian package per line')
    if len(names) != len(set(names)):
        raise ValueError('duplicate Debian package')
    return names


def words(group, key, required=False):
    values = group.get(key, [])
    if (not isinstance(values, list) or (required and not values)
            or any(not isinstance(value, str) or not value for value in values)
            or len(values) != len(set(values))):
        raise ValueError(f'invalid or duplicate {key}: {values!r}')
    return values


def scope():
    spec = importlib.util.spec_from_file_location('loadable_catalog', ROOT / 'config/loadables.py')
    catalog = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(catalog)
    full = catalog.parse_list(ROOT / 'config/bash-loadables.list')
    optional = catalog.parse_list(ROOT / 'config/bash-loadables-optional.list')
    if full.keys() & optional.keys():
        raise ValueError('overlapping full and optional catalogs')
    known = full | optional
    packages = package_list(HERE / 'packages.list')
    mapping = json.loads((HERE / 'references.json').read_text())
    if mapping.get('schema') != 1 or not isinstance(mapping.get('groups'), list):
        raise ValueError('unsupported reference mapping schema')
    rows = {}
    for group in mapping['groups']:
        if group.get('kind') not in KINDS or not isinstance(group.get('notes'), str) or not group['notes'].strip():
            raise ValueError('each group needs a reference kind and an explicit scope note')
        if set(group) - {'loadables', 'kind', 'packages', 'programs', 'python_modules', 'notes'}:
            raise ValueError('unknown reference group field')
        names = words(group, 'loadables', required=True)
        required_packages = words(group, 'packages')
        if set(required_packages) - set(packages):
            raise ValueError('reference group requires undeclared Debian packages')
        programs = words(group, 'programs') if 'programs' in group else names
        modules = words(group, 'python_modules')
        if any(not MODULE.fullmatch(module) for module in modules):
            raise ValueError('invalid Python module name')
        if any(any(char.isspace() for char in program) for program in programs):
            raise ValueError('programs must be executable names or paths, not shell commands')
        if not programs and not modules:
            raise ValueError('reference group has no supporting tools or APIs')
        for name in names:
            if name in rows:
                raise ValueError('duplicate loadable mapping: ' + name)
            rows[name] = {'name': name, 'optional': name in optional,
                          'kind': group['kind'], 'programs': programs,
                          'python_modules': modules, 'packages': required_packages,
                          'notes': group['notes']}
    missing, stale = known.keys() - rows.keys(), rows.keys() - known.keys()
    if missing or stale:
        raise ValueError(f'catalog mapping drift: unmapped={sorted(missing)}, stale={sorted(stale)}')
    return {
        'schema': 1,
        'claim': mapping['claim'],
        'full_catalog_count': len(full),
        'optional_catalog_count': len(optional),
        'reference_kinds': dict(sorted(Counter(row['kind'] for row in rows.values()).items())),
        'inputs_sha256': {str(path.relative_to(ROOT)): sha256(path) for path in (
            ROOT / 'config/bash-loadables.list', ROOT / 'config/bash-loadables-optional.list',
            ROOT / 'config/versions.sh', ROOT / 'config/uv.json',
            HERE / 'references.json', HERE / 'packages.list', HERE / 'inventory.py', HERE / 'util-linux.json')},
        'required_debian_packages': packages,
        'loadables': [rows[name] for name in sorted(rows)],
    }


def capture(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=90).stdout


def audit(report):
    errors = []
    # Inspect presence only: never start services or run privileged reference tools.
    programs = sorted({program for row in report['loadables'] for program in row['programs']})
    found = {program: shutil.which(program) for program in programs}
    errors += ['missing executable: ' + program for program, path in found.items() if path is None]
    modules = sorted({module for row in report['loadables'] for module in row['python_modules']})
    probe = '''import importlib.util,json,sys
found={}
for name in json.loads(sys.argv[1]):
    try:
        found[name]=importlib.util.find_spec(name) is not None
    except (ImportError,ModuleNotFoundError,ValueError):
        found[name]=False
print(json.dumps(found))
'''
    module_state = json.loads(capture(['/usr/bin/python3', '-c', probe, json.dumps(modules)]))
    errors += ['missing Python API: ' + name for name, present in module_state.items() if not present]
    package_output = capture(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
    installed = {}
    for line in package_output.splitlines():
        name, version, status = line.split('\t')
        if status == 'installed':
            installed[name.split(':')[0]] = version
    errors += ['missing Debian package: ' + name for name in report['required_debian_packages'] if name not in installed]
    bash = Path('/opt/bash-reference/bin/bash')
    versions = (ROOT / 'config/versions.sh').read_text()
    base = re.search(r'^BASH_SRC_VERSION=([0-9.]+)$', versions, re.M).group(1)
    patch = re.search(r'^BASH_PATCHLEVEL=([0-9]+)\b', versions, re.M).group(1)
    expected_bash = base + '.' + patch
    bash_version = capture([str(bash), '--version']).splitlines()[0]
    if f'version {expected_bash}(' not in bash_version:
        errors.append('reference Bash differs from config/versions.sh')
    # A stock reference shell must not silently resolve any loadable as a builtin.
    builtin_names = set(capture([str(bash), '--noprofile', '--norc', '-c', 'compgen -b']).splitlines())
    injected = sorted(builtin_names & {row['name'] for row in report['loadables']})
    if injected:
        errors.append('reference Bash contains candidate builtins: ' + ', '.join(injected))
    uv = Path('/usr/local/bin/uv')
    uv_version = capture([str(uv), '--version']).strip()
    uv_pin = json.loads((ROOT / 'config/uv.json').read_text())['version']
    if not uv_version.startswith('uv ' + uv_pin + ' ') and uv_version != 'uv ' + uv_pin:
        errors.append('reference uv differs from config/uv.json')
    util_pin = json.loads((HERE / 'util-linux.json').read_text())
    util_programs = {}
    for name in util_pin['programs']:
        path = Path('/opt/util-linux-reference/bin') / name
        version = capture([str(path), '--version']).strip()
        if 'util-linux ' + util_pin['version'] not in version:
            errors.append('supplemental util-linux reference version differs: ' + name)
        util_programs[name] = {'path': str(path), 'version': version, 'sha256': sha256(path)}
    report.update({
        'image_audit': 'PASS' if not errors else 'FAIL',
        'errors': errors,
        'architecture': capture(['dpkg', '--print-architecture']).strip(),
        'debian_snapshot': Path('/etc/bash-os-parity-snapshot').read_text().strip(),
        'installed_debian_packages': dict(sorted(installed.items())),
        'executables': found,
        'python_apis': module_state,
        'python_version': sys.version,
        'reference_bash': {'path': str(bash), 'version': bash_version, 'sha256': sha256(bash)},
        'reference_uv': {'path': str(uv), 'version': uv_version, 'sha256': sha256(uv)},
        'reference_util_linux': {'source': util_pin, 'programs': util_programs},
        'qualification': 'Tool/API availability only. No behavioral parity or kernel/hardware result is inferred.',
    })
    return not errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='check mapping completeness without executing reference tools')
    mode.add_argument('--check-image', action='store_true', help='audit installed image tools, packages and APIs')
    parser.add_argument('--format', choices=['json', 'tsv'], default='json')
    args = parser.parse_args()
    try:
        report = scope()
        passed = audit(report) if args.check_image else True
        for error in report.get('errors', []):
            print('parity-reference-inventory: ' + error, file=sys.stderr)
        if args.check:
            report = {key: report[key] for key in ('full_catalog_count', 'optional_catalog_count', 'reference_kinds')}
        if args.format == 'tsv':
            if args.check:
                parser.error('--format tsv requires the full inventory')
            print('loadable\toptional\tkind\treference_programs\tpython_apis\tscope')
            for row in report['loadables']:
                print('\t'.join((row['name'], str(row['optional']).lower(), row['kind'],
                                 ' '.join(row['programs']), ' '.join(row['python_modules']), row['notes'])))
        else:
            print(json.dumps(report, indent=2))
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('parity-reference-inventory: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
