#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Completing-anchor '+' separators match GNU tac on the original pattern.

A nullable group containing \\' \\b or \\B is not the XX* spelling: GNU
finishes the original and the spans differ, in the C locale and in UTF-8.
A non-nullable '+' whose operand contains \\` can finish too, and XX* can
disagree (\\(\\`+?\\|\\s\\)+ returns the input unchanged). A nullable '+'
that also contains a hang anchor is refused. A nullable hang-anchor '+'
still has to finish as the XX* spelling, because GNU does not return.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

REFERENCE = '/usr/bin/tac'
REFUSE = b'cannot be matched safely'
LOCALES = ('C', 'C.UTF-8', 'en_US.UTF-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=lambda s: str(Path(s).resolve()))
    ap.add_argument('--module', help='Replacement tac module')
    ap.add_argument('--timeout', type=int, default=5)
    ap.add_argument('--vm-kb', type=int, default=1048576)
    args = ap.parse_args()
    script = r'''
if [[ -n ${TAC_MODULE-} ]]; then enable -f "$TAC_MODULE" tac || exit; fi
if [[ -n ${TAC_VM_KB-} ]]; then ulimit -v "$TAC_VM_KB" || exit; fi
args=(-r -s "$SEP")
if [[ -n ${BEFORE-} ]]; then args=(-b "${args[@]}"); fi
if [[ -n ${FILE-} ]]; then args+=("$FILE"); fi
tac "${args[@]}"
'''
    # kind gnu: builtin must match GNU on the original pattern.
    # kind spell: GNU does not return; builtin must match the XX* spelling.
    # kind refuse: neither search is safe.
    end = "\\(\\|\\'b\\)"
    cases = [
        ('end', end + '+', b'.b', False, False, 'gnu'),
        ('end', end + '+', b'.b', True, False, 'gnu'),
        ('end', end + '+', b'ab\n.b\n', False, False, 'gnu'),
        ('end', end + '+', b'b.b.b', False, False, 'gnu'),
        ('end-tail', "\\(\\'b\\|\\)+", b'ab\n.b\n', False, False, 'gnu'),
        ('end-nested', '\\(' + end + '+\\)', b'ab\n.b\n', False, False, 'gnu'),
        ('end-plus-plus', end + '++', b'.b', False, False, 'gnu'),
        ('end-plus-star', end + '+*', b'ab\n.b\n', False, False, 'gnu'),
        ('end-pipe', end + '+', b'ab\n.b\n', False, True, 'gnu'),
        ('word', '\\(\\|\\bb\\)+', b'ab\n.b\n', False, False, 'gnu'),
        ('word', '\\(\\|\\bb\\)+', b'.b', False, False, 'gnu'),
        ('word-tail', '\\(\bb\\|\\)+', b'ab\n.b\n', False, False, 'gnu'),
        ('nonword', '\\(\\|\\Bb\\)+', b'.b', False, False, 'gnu'),
        ('nonword', '\\(\\|\\Bb\\)+', b'ab\n.b\n', False, False, 'gnu'),
        ('nonword-nested', '\\(\\(\\|\\Bb\\)+\\)', b'b.b.b', False, False, 'gnu'),
        ('mixed', '\\(\\|\\`\\|\\\'b\\)+', b'.b', False, False, 'refuse'),
        ('mixed', '\\(\\|\\`\\|\\\'b\\)+', b'.b', True, False, 'refuse'),
        ('beg-literal', '\\(\\`+?\\|\\s\\)+', b'\n\n:', False, False, 'gnu'),
        ('beg-literal', '\\(\\`+?\\|\\s\\)+', b'\n\n:', True, False, 'gnu'),
        ('hang-beg', '\\(\\|\\`b\\)+', b'.b\nab\n', False, False, 'spell'),
    ]
    spelled = {
        end + '+': end + end + '*',
        '\\(\\|\\`b\\)+': '\\(\\|\\`b\\)\\(\\|\\`b\\)*',
    }
    asan = bool(os.environ.get('ASAN_OPTIONS'))
    vm = '' if asan or args.vm_kb <= 0 else str(args.vm_kb)
    base = dict(os.environ)
    base['PATH'] = '/usr/bin:/bin'
    for name in ('LANG', 'LANGUAGE', 'POSIXLY_CORRECT'):
        base.pop(name, None)
    if args.module:
        base['TAC_MODULE'] = str(Path(args.module).resolve())
    else:
        base.pop('TAC_MODULE', None)
    base['TAC_VM_KB'] = vm
    checks = mismatches = 0
    with tempfile.TemporaryDirectory(prefix='grok-tac-c1-') as directory:
        root = Path(directory)
        base['TMPDIR'] = str(root)
        source = root / 'input'
        for locale in LOCALES:
            for name, pattern, payload, before, pipe, kind in cases:
                env = dict(base, LC_ALL=locale, SEP=pattern,
                           BEFORE='1' if before else '', FILE='')
                stdin = payload if pipe else None
                if not pipe:
                    source.write_bytes(payload)
                    env['FILE'] = str(source)
                got = subprocess.run(
                    ['/usr/bin/timeout', '-k', '1', str(args.timeout), args.binary,
                     '--noprofile', '--norc', '-c', script, '_'],
                    input=stdin, env=env, capture_output=True, timeout=args.timeout + 5)
                label = f'{locale} {name} before={int(before)} pipe={int(pipe)}'
                checks += 1
                if kind == 'refuse':
                    ok = (got.returncode == 1 and not got.stdout and REFUSE in got.stderr)
                    if ok:
                        print(f'OK {label} refused')
                    else:
                        mismatches += 1
                        print(f'MISMATCH {label} wanted refusal '
                              f'rc={got.returncode} out={got.stdout[:80]!r} '
                              f'err={got.stderr[:160]!r}')
                    continue
                oracle = spelled[pattern] if kind == 'spell' else pattern
                gargs = ['-r', '-s', oracle]
                if before:
                    gargs = ['-b', *gargs]
                genv = dict(base, LC_ALL=locale)
                if pipe:
                    cmd = ['/usr/bin/timeout', '-k', '1', str(args.timeout), REFERENCE, *gargs]
                    gstdin = payload
                else:
                    cmd = ['/usr/bin/timeout', '-k', '1', str(args.timeout),
                           REFERENCE, *gargs, env['FILE']]
                    gstdin = None
                ref = subprocess.run(cmd, input=gstdin, env=genv, capture_output=True,
                                     timeout=args.timeout + 5)
                if kind == 'gnu' and name == 'end' and payload == b'.b' and not before:
                    spell = subprocess.run(
                        ['/usr/bin/timeout', '-k', '1', str(args.timeout), REFERENCE,
                         '-r', '-s', spelled[pattern], env['FILE']],
                        env=genv, capture_output=True, timeout=args.timeout + 5)
                    if spell.returncode == 0 and spell.stdout == ref.stdout:
                        mismatches += 1
                        print(f'MISMATCH {label} XX* agrees with GNU; '
                              'this case does not show the defect')
                        continue
                if got.returncode in (124, 137) or ref.returncode in (124, 137):
                    mismatches += 1
                    print(f'TIMEOUT {label} builtin={got.returncode} gnu={ref.returncode}')
                elif (got.returncode, got.stdout) != (ref.returncode, ref.stdout):
                    mismatches += 1
                    print(f'MISMATCH {label} builtin={got.returncode} gnu={ref.returncode} '
                          f'out={got.stdout[:80]!r} gnu_out={ref.stdout[:80]!r} '
                          f'err={got.stderr[:120]!r}')
                else:
                    print(f'OK {label}')
    print(f'grok-tac-c1-parity: {checks} checks, {mismatches} mismatches')
    if mismatches:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
