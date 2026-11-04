#!/usr/bin/env python3
"""Disposable user/PID-namespace regression; reuse the guarded lsof fixture."""
import importlib.util
from pathlib import Path
import pwd
import sys

path = Path('/opt/bashos-parity/harness/helpers/namespace-network-lsof-r1.py')
spec = importlib.util.spec_from_file_location('lsof_fixture', path)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
f.guard()
if f.os.getpid() != 1 or pwd.getpwuid(0).pw_name != 'root':
    raise RuntimeError('invalid namespace or root account')
other = pwd.getpwnam('nobody')
if other.pw_uid == 0:
    raise RuntimeError('nobody is not a distinct UID')
children = []
result = {'calls': {}, 'errors': []}
try:
    children.append(f.spawn('union-a'))
    children.append(f.spawn('union-b'))
    f.native_for_children(children, {'children': [], 'control_errors': result['errors']})
    if result['errors']:
        raise RuntimeError('native descriptor control failed')
    p1, p2 = [info['pid'] for _, info in children]
    cases = [
        ('or-name', ['-p', str(p1), '-u', 'nobody'], {p1}),
        ('or-uid', ['-u', str(other.pw_uid), '-p', str(p1)], {p1}),
        ('and-name', ['-p', str(p1), '-a', '-u', 'nobody'], set()),
        ('and-uid', ['-u', str(other.pw_uid), '-a', '-p', str(p1)], set()),
        ('and-match', ['-p', str(p1), '-u', 'root', '-a'], {p1}),
        ('or-match', ['-p', str(p1), '-u', 'root'], {p1, p2}),
    ]
    for label, args, want in cases:
        native = f.ref_run(args)
        native_rows = f.ref_rows(f.raw_output(native))
        native_selected = {r['pid'] for r in native_rows if r['pid'] in {p1, p2}}
        result['calls'][label] = {'native': native, 'native_selected': sorted(native_selected)}
        if native['status'] not in (0, 1) or native_selected != want:
            raise RuntimeError('native selector control failed: ' + label)
        call = f.invoke(sys.argv[1], args, label, children)
        rows = f.candidate_rows(f.raw_output(call))
        selected = f.selected_children(rows, children)
        result['calls'][label] = {'native': native, 'native_selected': sorted(native_selected),
                                  'candidate': call, 'selected': sorted(selected)}
        if call['status'] != 0 or call['shell_status'] != 0 or selected != want:
            result['errors'].append(label)
        if label.startswith('and-') and any(r['pid'] != p1 for r in rows):
            result['errors'].append(label + ': unrelated PID')
    if result['errors']:
        raise RuntimeError('candidate selection failed: ' + repr(result['errors']))
    print('user_union=ok')
finally:
    f.record('user-union.json', result)
    f.release(children)
