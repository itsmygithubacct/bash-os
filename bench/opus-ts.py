#!/usr/bin/env python3
"""Self-timed ts parser/query/span/highlight/edit workloads with validated output.

bench/opus-ts.py --binary out/bash-X [--binary out/bash-Y ...] --output R.json
                 [--cpu N] [--runs 7] [--passes P]

For each workload the expected output of one pass is fixed before timing:
span and render outputs must equal what the precedence oracle in
tests/opus-ts-highlight.py derives from raw `ts query` captures, parse output
must contain one (number) per array element. A sample is one shell process
running PASSES passes in-process (empty PATH, builtins only) with stdout to a
private file; the whole file must equal PASSES copies of the expected output
or the binary is marked invalid for that workload and gets no timing. One
warm-up sample precedes RUNS timed samples. There is no external reference:
these are self timings, comparable only with another run of the same
workload on the same host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))

JSON_SCM = ('(pair key: (_) @string.special.key) (string) @string (number) @number '
            '[(null) (true) (false)] @constant.builtin (escape_sequence) @escape (comment) @comment')
BASH_SCM = ('(comment) @comment (string) @string (raw_string) @string (ansi_c_string) @string '
            '(translated_string) @string (number) @number (variable_name) @variable '
            '(simple_expansion) @variable (command_name) @function '
            '(function_definition name: (word) @function)')
CODES = {'string.special.key': '1;36', 'string': '32', 'number': '33', 'constant.builtin': '35',
         'escape': '1;33', 'comment': '90', 'variable': '37', 'function': '36'}


def fixtures():
    obj = json.dumps({'answer': 42, 'data': [i % 101 for i in range(10000)]}).encode() + b'\n'
    arr = json.dumps([i % 101 for i in range(10000)]).encode() + b'\n'
    keys = json.dumps([{'id': i, 'name': f'n\t{i}', 'tags': ['a', 'é'], 'ok': i % 2 == 0,
                        'nested': {'k': None, 'v': i / 4}} for i in range(1000)]).encode() + b'\n'
    lines = []
    for i in range(1000):
        lines.append(f'f{i}() {{ echo "v $x{i} ${{y}}" \'raw\' {i} # c{i}\n}}')
    sh = '\n'.join(lines).encode() + b'\n'
    return {'array': arr, 'object': obj, 'keys': keys, 'bash': sh}


def oracle_owner(binary, lang, scm, data):
    """Per-byte winning capture by the documented rule, from raw `ts query`."""
    order = {n: i for i, n in enumerate(dict.fromkeys(re.findall(r'@([\w.]+)', scm)))}
    p = subprocess.run([binary, '--norc', '--noprofile', '-c', 'PATH=; ts query -L "$1" -q "$2"', '_',
                        lang, scm], input=data, capture_output=True, check=True)
    caps = []
    for line in p.stdout.decode('utf-8', 'replace').splitlines():
        name, _, rng = line.split(' ', 3)[:3]
        sb, eb = map(int, rng.split('-'))
        if sb < eb:
            caps.append((sb, eb, name))
    owner = [None] * len(data)
    for sb, eb, name in sorted(caps, key=lambda c: (-(c[1] - c[0]), -order[c[2]], -c[0])):
        owner[sb:eb] = [name] * (eb - sb)
    return owner


def runs_of(owner):
    b = 0
    while b < len(owner):
        e = b + 1
        while e < len(owner) and owner[e] == owner[b]:
            e += 1
        yield b, e, owner[b]
        b = e


def oracle_spans(owner):
    return b''.join(f'{b}-{e} {CODES[o]} {o}\n'.encode() for b, e, o in runs_of(owner) if o)


def oracle_render(owner, data):
    out, cur = [], None
    for b, e, o in runs_of(owner):
        code = CODES[o] if o else None
        if code != cur:
            if cur:
                out.append(b'\x1b[0m')
            if code:
                out.append(b'\x1b[' + code.encode() + b'm')
            cur = code
        out.append(data[b:e])
    if cur:
        out.append(b'\x1b[0m')
    return b''.join(out)


def workloads(oracle_binary, fx, tmp):
    """(label, script, input file, expected one-pass output, work dict)."""
    out = []
    for name, data in fx.items():
        (tmp / name).write_bytes(data)
    arr = fx['array']
    out.append(('ts-parse', 'ts parse -L json < "$F"', 'array', None,
                {'input_bytes': len(arr), 'elements': 10000}))
    q = '(pair key: (_) @key) (number) @num (string) @str'
    out.append(('ts-query', f'ts query -L json -q {q!r} < "$F"', 'object', None,
                {'input_bytes': len(fx['object']), 'captures': 10005}))
    for lang, scm, fxname in [('json', JSON_SCM, 'object'), ('json', JSON_SCM, 'keys'),
                              ('bash', BASH_SCM, 'bash')]:
        data = fx[fxname]
        owner = oracle_owner(oracle_binary, lang, scm, data)
        spans = oracle_spans(owner)
        nspans = spans.count(b'\n')
        out.append((f'ts-spans-{fxname}', f'ts highlight -L {lang} -S < "$F"', fxname, spans,
                    {'input_bytes': len(data), 'resolved_spans': nspans}))
        rendered = oracle_render(owner, data)
        out.append((f'ts-render-{fxname}', f'ts highlight -L {lang} < "$F"', fxname, rendered,
                    {'input_bytes': len(data), 'resolved_spans': nspans, 'output_bytes': len(rendered)}))
    # Incremental: alternately insert and remove one key/value pair near the
    # middle of the key-heavy fixture, re-highlighting the edited tree each time.
    keys = fx['keys']
    cut = keys.index(b'{"id": 500,')
    ins = b'{"inserted": "s\\n", "n": 1}, '
    edited = keys[:cut] + ins + keys[cut:]
    (tmp / 'keys-edited').write_bytes(edited)
    a = oracle_spans(oracle_owner(oracle_binary, 'json', JSON_SCM, edited))
    b = oracle_spans(oracle_owner(oracle_binary, 'json', JSON_SCM, keys))
    script = (f'ts edit $T {cut} {cut} {cut + len(ins)} -t T < "$G" && ts highlight -t $T -S && '
              f'ts edit $T {cut} {cut + len(ins)} {cut} -t T < "$F" && ts highlight -t $T -S')
    out.append(('ts-edit-highlight', script, 'keys', a + b,
                {'input_bytes': len(keys), 'edits': 2, 'edit_bytes': len(ins),
                 'resolved_spans': a.count(b'\n') + b.count(b'\n')}))
    return out


def sample(binary, script, inp, tmp, passes, cpu):
    outfile = tmp / 'out'
    setup = 'ts parse-tree -L json -t T < "$F" || exit 9; ' if '$T' in script else ''
    body = (f'PATH=; F=$1; G=$2; n=$3; {setup}'
            f'for ((i=0;i<n;i++)); do {script} || exit 8; done')
    env = {'LC_ALL': 'C', 'PATH': '/nonexistent', 'HOME': str(tmp)}
    pre = (lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None
    with open(outfile, 'wb') as fh:
        t0 = time.perf_counter()
        p = subprocess.run([binary, '--norc', '--noprofile', '-c', body, '_', str(tmp / inp),
                            str(tmp / 'keys-edited'), str(passes)],
                           stdout=fh, stderr=subprocess.PIPE, env=env, preexec_fn=pre)
        t1 = time.perf_counter()
    return p.returncode, outfile.read_bytes(), p.stderr, (t1 - t0) * 1000


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', action='append', required=True)
    ap.add_argument('--oracle-binary', help='binary whose raw `ts query` feeds the oracle (default: last --binary)')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cpu', type=int)
    ap.add_argument('--runs', type=int, default=7)
    ap.add_argument('--passes', type=int, default=5)
    ap.add_argument('--only')
    args = ap.parse_args()
    binaries = [str(Path(b).resolve()) for b in args.binary]
    oracle_binary = str(Path(args.oracle_binary or binaries[-1]).resolve())
    fx = fixtures()
    report = {'host': platform.node(), 'kernel': platform.release(), 'python': sys.version.split()[0],
              'cpu_affinity': args.cpu, 'runs': args.runs, 'warmup': 1, 'passes': args.passes,
              'oracle_binary': oracle_binary, 'reference': 'self (no external ratio)',
              'fixtures': {k: {'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest()} for k, v in fx.items()},
              'binaries': {b: sha(b) for b in binaries}, 'cases': []}
    with tempfile.TemporaryDirectory(prefix='opus-ts-bench-') as td:
        tmp = Path(td)
        loads = workloads(oracle_binary, fx, tmp)
        if args.only:
            keep = set(args.only.split(','))
            loads = [w for w in loads if w[0] in keep]
        for label, script, inp, expected, work in loads:
            if expected is None:
                # parse/query: the oracle is structural; the first valid pass of
                # the oracle binary becomes the byte-exact expectation for all.
                rc, one, err, _ = sample(oracle_binary, script, inp, tmp, 1, args.cpu)
                assert rc == 0, (label, err)
                if label == 'ts-parse':
                    assert one.count(b'(number)') == work['elements'] and b'ERROR' not in one, label
                else:
                    lines = one.decode().splitlines()
                    assert len(lines) == work['captures'], (label, len(lines))
                    assert sum(l.startswith('key ') for l in lines) == 2, label
                    assert sum(l.startswith('num ') for l in lines) == 10001, label
                expected = one
            work = {**work, 'expected_output_bytes': len(expected),
                    'expected_sha256': hashlib.sha256(expected).hexdigest()}
            for b in binaries:
                case = {'workload': label, 'binary': b, 'script': script, 'fixture': inp, 'work': work}
                rc, out, err, _ = sample(b, script, inp, tmp, args.passes, args.cpu)  # warm-up
                ok = rc == 0 and out == expected * args.passes
                samples = []
                if ok:
                    for _ in range(args.runs):
                        rc, out, err, ms = sample(b, script, inp, tmp, args.passes, args.cpu)
                        if rc != 0 or out != expected * args.passes:
                            ok = False
                            break
                        samples.append(round(ms, 3))
                case['status'] = 'ok' if ok else 'invalid-output'
                if not ok:
                    case['detail'] = {'rc': rc, 'stderr': err[:400].decode('utf-8', 'replace'),
                                      'output_bytes': len(out),
                                      'expected_bytes': len(expected) * args.passes}
                else:
                    case['samples_ms'] = samples
                    case['median_ms'] = round(statistics.median(samples), 3)
                    case['min_ms'] = min(samples)
                    case['max_ms'] = max(samples)
                    case['per_pass_median_ms'] = round(statistics.median(samples) / args.passes, 3)
                report['cases'].append(case)
                print(f"{label:22} {case['status']:15} {case.get('median_ms', '-'):>10} ms  {Path(b).name}",
                      flush=True)
    args.output.write_text(json.dumps(report, indent=1) + '\n')


if __name__ == '__main__':
    main()
