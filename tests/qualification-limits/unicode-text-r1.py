#!/usr/bin/env python3
"""Preserved TEXT interface against every non-NUL Unicode 17 corpus row."""
import importlib.util
from pathlib import Path
import sys
import tempfile
from guest import digest, entrypoint, guard, require_bash_5320, run, save


def main():
    guard()
    shell, corpus, output = sys.argv[1:]
    version = require_bash_5320(shell)
    spec = importlib.util.spec_from_file_location('corpus_data', Path(__file__).with_name('unicode-corpus.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = [row for row in module.corpus(corpus) if not row['nul']]
    checks = []
    with tempfile.TemporaryDirectory(prefix='qual-unicode-text-') as folder:
        root = Path(folder)
        script = ['set -u', '[[ $(type -t utf8) == builtin ]] || exit 125']
        expected = []
        for i, row in enumerate(rows):
            raw = bytes.fromhex(row['hex'])
            (root / f'{i}.in').write_bytes(raw)
            script += [f"IFS= read -r -d '' text <{i}.in || :", f"printf '%s' \"$text\" >{i}.roundtrip"]
            commands = [('grapheme', 'utf8 length "$text"', str(len(row['clusters'])).encode() + b'\n'),
                        ('codepoint', 'utf8 length "$text" -T codepoint', str(len(raw.decode('utf-8'))).encode() + b'\n'),
                        ('byte', 'utf8 length "$text" -T byte', str(len(raw)).encode() + b'\n')]
            commands += [(f'slice-{j}', f'utf8 slice "$text" {j} {j+1}', bytes.fromhex(cluster) + b'\n')
                         for j, cluster in enumerate(row['clusters'])]
            for label, command, wanted in commands:
                name = f'{i}-{label}'
                script += [f'{command} >{name}.out 2>{name}.err', f'printf "%s\\n" "$?" >{name}.rc']
                expected.append((name, row['line'], wanted))
        (root / 'case.sh').write_text('\n'.join(script) + '\n')
        execution = run([shell, '--noprofile', '--norc', str(root / 'case.sh')], cwd=root, timeout=40)
        for name, line, wanted in expected:
            paths = [root / (name + suffix) for suffix in ('.out', '.err', '.rc')]
            complete = all(p.is_file() for p in paths)
            actual, error, status = [p.read_bytes() for p in paths] if complete else (b'', b'', b'')
            checks.append(dict(case=name, line=line, complete=complete, actual_hex=actual.hex(), expected_hex=wanted.hex(),
                               stderr_hex=error.hex(), status_text=status.decode(errors='replace'),
                               matches=complete and actual == wanted and not error and status == b'0\n'))
        transport = all((root / f'{i}.roundtrip').is_file() and
                        (root / f'{i}.roundtrip').read_bytes() == bytes.fromhex(row['hex'])
                        for i, row in enumerate(rows))
    result = 'PASS' if transport and execution['status'] == 0 and all(c['matches'] for c in checks) else 'FAIL'
    if not transport or any(not c['complete'] for c in checks) or execution['status'] in (125, 126, 127):
        result = 'ERROR'
    save(output, dict(result=result, scope='TEXT interface non-NUL subset; NUL descriptor coverage is separate',
                      shell_sha256=digest(shell), bash_version=version, corpus_sha256=module.PIN,
                      rows=len(rows), argument_roundtrips=transport, execution=execution, checks=checks))
    return {'PASS': 0, 'FAIL': 1, 'ERROR': 125}[result]


if __name__ == '__main__':
    entrypoint(main)
