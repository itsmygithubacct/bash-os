#!/usr/bin/env python3
"""Compare cp --parents with GNU cp in identical, private filesystem fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


CASES = [
    ('nested', '', 'cp --parents src/sub/file out', 0),
    ('verbose', '', 'cp -v --parents src/sub/file out', 0),
    ('absolute', '', 'cp -v --parents "$PWD/src/sub/file" out', 0),
    ('dot-prefix', '', 'cp -v --parents ./src/sub/file out', 0),
    ('repeated-slashes', '', 'cp -v --parents src//sub///file out/', 0),
    ('interior-dotdot', 'mkdir src/empty', 'cp -v --parents src/empty/../sub/file out', 0),
    ('leading-dotdot', 'mkdir -p run/out', 'cd run; cp -v --parents ../src/sub/file out', 0),
    ('spaces-and-dash', "mkdir -p './-space name/sub dir'; printf data > './-space name/sub dir/a file'",
     "cp -v --parents -- '-space name/sub dir/a file' out", 0),
    ('multiple', 'printf other > src/other', 'cp --parents src/sub/file src/other out', 0),
    ('bare-file', 'printf single > file', 'cp --parents file out', 0),
    ('recursive', '', 'cp -Rv --parents src/sub/ out', 0),
    ('archive-links', 'ln src/sub/file src/sub/hard; ln -s file src/sub/link',
     'cp -a --parents src/sub/file src/sub/hard src/sub/link out', 0),
    ('source-symlink', 'ln -s file src/sub/link', 'cp -P --parents src/sub/link out', 0),
    ('follow-source-symlink', 'ln -s file src/sub/link', 'cp --parents src/sub/link out', 0),
    ('source-parent-symlink', 'ln -s sub src/alias', 'cp --parents src/alias/file out', 0),
    ('existing-parent', 'mkdir -p out/src/sub; chmod 700 out/src out/src/sub',
     'cp -p --parents src/sub/file out', 0),
    ('destination-parent-symlink', 'mkdir target; ln -s ../target out/src',
     'cp --parents src/sub/file out', 0),
    ('destination-file-symlink', 'mkdir -p out/src/sub; printf old > target; ln -s ../../../target out/src/sub/file',
     'cp --parents src/sub/file out', 0),
    ('umask', 'chmod 751 src; chmod 511 src/sub', 'umask 027; cp --parents src/sub/file out', 0),
    ('restrictive-umask', '', 'umask 0777; cp --parents src/sub/file out', 0),
    ('special-parent-modes', 'chmod 1755 src; chmod 2755 src/sub', 'cp --parents src/sub/file out', 0),
    ('inherit-setgid', 'chmod 2755 out', 'cp --parents src/sub/file out', 0),
    ('setuid-parent', 'chmod 4755 src', 'cp --parents src/sub/file out', 0),
    ('readonly-multiple', 'printf more > src/sub/second; chmod 555 src/sub',
     'cp --parents src/sub/file src/sub/second out', 1),
    ('preserve-metadata', 'chmod 751 src; chmod 511 src/sub; touch -d @1234567890 src src/sub src/sub/file',
     'cp -p --parents src/sub/file out; stat -c "%a %Y" out/src out/src/sub out/src/sub/file', 0),
    ('no-clobber', 'mkdir -p out/src/sub; printf keep > out/src/sub/file',
     'cp -n --parents src/sub/file out', 0),
    ('overwrite', 'mkdir -p out/src/sub; printf old > out/src/sub/file',
     'cp --parents src/sub/file out', 0),
    ('missing-destination', '', 'cp --parents src/sub/file absent', 1),
    ('file-destination', 'printf keep > target', 'cp --parents src/sub/file target', 1),
    ('parent-collision', 'printf keep > out/src', 'cp --parents src/sub/file out', 1),
    ('missing-source-parent', '', 'cp --parents missing/sub/file out', 1),
    ('missing-source-file', 'chmod 511 src/sub', 'cp --parents src/sub/missing out', 1),
    ('source-parent-file', '', 'cp --parents src/sub/file/child out', 1),
    ('dangling-parent-symlink', 'ln -s missing out/src', 'cp --parents src/sub/file out', 1),
    ('directory-without-recursion', '', 'cp --parents src/sub/ out', 1),
    ('failure-then-success', '', 'cp --parents missing/sub/file src/sub/file out', 1),
    ('repeated-invocations', '', 'cp --parents src/sub/file out; cp src/sub/file plain; cp --parents src/sub/file out', 0),
    ('too-long-source', '', "printf -v path '%5000s' ''; cp --parents \"${path// /x}\" out", 1),
]


def snapshot(root):
    entries, links = {}, {}
    def visit(path):
        info = path.lstat()
        name = str(path.relative_to(root))
        mode = stat.S_IMODE(info.st_mode)
        item = {'mode': mode}
        entries[name] = item
        if path.is_symlink():
            item.update(kind='symlink', target=os.readlink(path))
        elif path.is_dir():
            item['kind'] = 'directory'
            path.chmod(mode | 0o700)
            try:
                for child in sorted(path.iterdir()):
                    visit(child)
            finally:
                path.chmod(mode)
        elif path.is_file():
            path.chmod(mode | 0o400)
            try:
                item.update(kind='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                            hardlink=links.setdefault((info.st_dev, info.st_ino), name))
            finally:
                path.chmod(mode)
        else:
            raise AssertionError('unexpected fixture type: ' + name)
    visit(root)
    return entries


def clean(root):
    for parent, dirs, _ in os.walk(root):
        os.chmod(parent, 0o700)
        for name in dirs:
            path = Path(parent) / name
            if not path.is_symlink():
                path.chmod(0o700)
    shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    env = {**os.environ, 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC', 'PATH': '/usr/bin:/bin'}
    env.pop('BASH_ENV', None)
    subprocess.run([args.binary, '--noprofile', '--norc', '-c',
                    '[[ $(type -t cp) == builtin ]]'], env=env, check=True)
    records = []
    with tempfile.TemporaryDirectory(prefix='cp-parents-') as directory:
        root = Path(directory) / 'fixture'
        for name, setup, code, status in CASES:
            results = []
            try:
                for shell in ('/bin/bash', args.binary):
                    if root.exists():
                        clean(root)
                    root.mkdir()
                    subprocess.run(['/bin/bash', '-c', "umask 022; set -e; mkdir -p src/sub out; printf 'hello\\0world\\n' > src/sub/file; " + setup],
                                   cwd=root, env=env, check=True, capture_output=True)
                    result = subprocess.run([shell, '--noprofile', '--norc', '-c', 'umask 022; ' + code],
                                            cwd=root, env=env, capture_output=True, timeout=10)
                    results.append({'status': result.returncode, 'stdout': result.stdout.hex(),
                                    'stderr': result.stderr.decode(errors='replace'), 'tree': snapshot(root)})
                left, right = results
                differences = [key for key in ('status', 'stdout', 'tree') if left[key] != right[key]]
                if left['status'] != status:
                    differences.append('reference expected status')
                if bool(left['stderr']) != bool(right['stderr']):
                    differences.append('diagnostic presence')
                if 'AddressSanitizer' in right['stderr'] or 'runtime error:' in right['stderr']:
                    differences.append('sanitizer')
                records.append({'case': name, 'passed': not differences, 'differences': differences,
                                'reference': left, 'candidate': right})
                print(('PASS ' if not differences else 'FAIL ') + name + (': ' + ', '.join(differences) if differences else ''), flush=True)
            finally:
                if root.exists():
                    clean(root)
    if args.output:
        args.output.write_text(json.dumps(records, indent=2) + '\n')
    failures = sum(not item['passed'] for item in records)
    print(f'cp --parents: {len(records) - failures}/{len(records)} passed')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
