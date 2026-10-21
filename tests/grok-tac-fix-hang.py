#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tac -r must finish anchor-plus separators and match the XX* spelling.

glibc's copy of X+ does not return for an empty alternative plus an anchor,
and it can return a different span for the same shape with other anchors.
The oracle is GNU tac on the spelled-out XX* form, which is the result the
bounded matcher already returns in the C locale. Each probe is under
timeout and, except under ASan, an address-space limit.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

REFERENCE = '/usr/bin/tac'
UNSUPPORTED = b'requires the GNU regex API'
ANCHORS = (
    ('begbuf', '\\`', False),
    ('caret', '^', False),
    ('dollar', '$', False),
    ('endbuf', "\\'", False),
    ('bow', '\\<', True),
    ('eow', '\\>', True),
    ('word', '\\b', True),
    ('nonword', '\\B', True),
)
LOCALES = ('C', 'C.UTF-8', 'en_US.UTF-8')


def forms(anchor):
    """(name, pattern, oracle, nullable, backref). Oracle is the XX* spelling."""
    empty = '\\(\\|' + anchor + 'b\\)'
    nested = '\\(' + empty + '+\\)'
    tail = '\\(' + anchor + 'b\\|\\)'
    plain = '\\(' + anchor + 'b\\)'
    return (
        ('empty-or-anch-lit-plus', empty + '+', empty + empty + '*', True, False),
        ('anch-lit-or-empty-plus', tail + '+', tail + tail + '*', True, False),
        ('nested-empty-or-anch-lit-plus', nested, '\\(' + empty + empty + '*\\)', True, False),
        ('anch-lit-plus', plain + '+', plain + plain + '*', False, False),
        ('empty-or-anch-lit-star', empty + '*', empty + '*', True, False),
    )


def build_cases():
    cases = []
    for name, anchor, word in ANCHORS:
        for kind, pattern, oracle, nullable, backref in forms(anchor):
            cases.append(dict(name=f'{name}-{kind}', pattern=pattern, oracle=oracle,
                              nullable=nullable, word=word, backref=backref,
                              glibc_only=False, payload=b'.b\nab\n', before=False,
                              pipe=False))
    # The three reported probes, with the separator attached before the record.
    reported = (('begbuf', '\\`', False), ('caret', '^', False), ('bow', '\\<', True))
    for name, anchor, word in reported:
        empty = '\\(\\|' + anchor + 'b\\)'
        cases.append(dict(name=f'{name}-empty-or-before', pattern=empty + '+',
                          oracle=empty + empty + '*', nullable=True, word=word,
                          backref=False, glibc_only=False, payload=b'.b\nab\n',
                          before=True, pipe=False))
    # Stacked quantifiers. The outer operator binds to the whole XX* piece.
    inner = '\\(\\|\\`b\\)'
    once = inner + inner + '*'
    wrapped = '\\(' + once + '\\)'
    cases.append(dict(name='begbuf-stacked-plus', pattern=inner + '++',
                      oracle=wrapped + wrapped + '*', nullable=True, word=False,
                      backref=False, glibc_only=False, payload=b'.b\nab\n',
                      before=False, pipe=False))
    cases.append(dict(name='begbuf-plus-star', pattern=inner + '+*',
                      oracle=wrapped + '*', nullable=True, word=False,
                      backref=False, glibc_only=False, payload=b'.b\nab\n',
                      before=False, pipe=False))
    # Back-references stay on the original pattern: duplicating groups would
    # renumber captures. The oracle is GNU on that same pattern.
    for name, pattern, payload in (
            ('backref-simple', '\\(a\\)\\1', b'aabaab\n'),
            ('backref-anchor-plus', '\\(\\(\\|\\`b\\)+\\)\\1', b'.b\nab\n'),
            ('backref-nested-anchor', '\\(\\(b\\)\\|\\`\\)+\\1', b'.b\nab\n')):
        cases.append(dict(name=name, pattern=pattern, oracle=pattern, nullable=True,
                          word=False, backref=True, glibc_only=False, payload=payload,
                          before=False, pipe=False))
    # Nullable, no anchor: glibc's own '+' is the oracle. Rewriting it is not
    # required, and refusing it would drop a result GNU returns.
    cases.append(dict(name='nullable-no-anchor', pattern='\\(a\\|\\)+',
                      oracle='\\(a\\|\\)+', nullable=True, word=False, backref=False,
                      glibc_only=False, payload=b'ab\nba\n', before=False, pipe=False))
    cases.append(dict(name='utf8-dot', pattern='.', oracle='.', nullable=False,
                      word=False, backref=False, glibc_only=False, payload=b'ab\ncd\n',
                      before=False, pipe=False))
    # A collating element keeps the pattern on glibc even in the C locale,
    # so the anchor-plus beside it used to loop there too.
    cases.append(dict(name='collating-anchor-plus',
                      pattern='[[.a.]]\\(\\|\\`b\\)+',
                      oracle='[[.a.]]\\(\\|\\`b\\)\\(\\|\\`b\\)*',
                      nullable=True, word=False, backref=False, glibc_only=True,
                      payload=b'.b\nab\n', before=False, pipe=False))
    # Same three shapes on a multibyte character, so a word anchor has to
    # keep glibc's wide class. The oracle is still GNU's XX* spelling.
    wide = 'é.b\nab\n'.encode()
    for name, anchor, word in ANCHORS:
        if not word:
            continue
        for kind, pattern, oracle, nullable, backref in forms(anchor)[:3]:
            cases.append(dict(name=f'wide-{name}-{kind}', pattern=pattern, oracle=oracle,
                              nullable=nullable, word=word, backref=backref,
                              glibc_only=False, payload=wide, before=False, pipe=False))
    # One pipe, so the spool path uses the same compiled pattern.
    empty = '\\(\\|\\`b\\)'
    cases.append(dict(name='begbuf-pipe', pattern=empty + '+', oracle=empty + empty + '*',
                      nullable=True, word=False, backref=False, glibc_only=False,
                      payload=b'.b\nab\n', before=False, pipe=True))
    return cases


def portable_unsupported(case, utf8):
    if case['backref'] or case['glibc_only']:
        return True
    if not utf8:
        return False
    if case['name'] == 'utf8-dot':
        return True
    return case['nullable'] or case['word']


def run_shell(binary, script, environment, stdin, timeout):
    return subprocess.run(
        ['/usr/bin/timeout', '-k', '1', str(timeout), binary, '--noprofile', '--norc',
         '-c', script, '_'],
        input=stdin, env=environment, capture_output=True, timeout=timeout + 5)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=lambda s: str(Path(s).resolve()))
    ap.add_argument('--module', help='Replacement tac module for sanitizer runs')
    ap.add_argument('--portable', action='store_true',
                    help='Build without the GNU regex API')
    ap.add_argument('--timeout', type=int, default=5)
    ap.add_argument('--vm-kb', type=int, default=1048576,
                    help='Address-space limit in KiB; 0 disables it')
    args = ap.parse_args()
    script = r'''
if [[ -n ${TAC_MODULE-} ]]; then enable -f "$TAC_MODULE" tac || exit; fi
if [[ -n ${TAC_VM_KB-} ]]; then ulimit -v "$TAC_VM_KB" || exit; fi
args=(-r -s "$SEP")
if [[ -n ${BEFORE-} ]]; then args=(-b "${args[@]}"); fi
if [[ -n ${FILE-} ]]; then args+=("$FILE"); fi
tac "${args[@]}"
'''
    asan = bool(os.environ.get('ASAN_OPTIONS'))
    vm = '' if asan or args.vm_kb <= 0 else str(args.vm_kb)
    base = dict(os.environ)
    base['PATH'] = '/usr/bin:/bin'
    base.pop('LANG', None)
    base.pop('LANGUAGE', None)
    base.pop('POSIXLY_CORRECT', None)
    if args.module:
        base['TAC_MODULE'] = str(Path(args.module).resolve())
    else:
        base.pop('TAC_MODULE', None)
    base['TAC_VM_KB'] = vm
    oracle = {}
    checks = timeouts = mismatches = 0
    with tempfile.TemporaryDirectory(prefix='grok-tac-hang-') as directory:
        root = Path(directory)
        base['TMPDIR'] = str(root)
        for case in build_cases():
            for locale in LOCALES:
                utf8 = locale != 'C'
                env = dict(base, LC_ALL=locale, SEP=case['pattern'],
                           BEFORE='1' if case['before'] else '', FILE='')
                stdin = None
                if case['pipe']:
                    stdin = case['payload']
                else:
                    source = root / 'input'
                    source.write_bytes(case['payload'])
                    env['FILE'] = str(source)
                got = run_shell(args.binary, script, env, stdin, args.timeout)
                label = f"{locale} {case['name']}"
                if args.portable and portable_unsupported(case, utf8):
                    ok = (got.returncode == 1 and not got.stdout and UNSUPPORTED in got.stderr)
                    checks += 1
                    if ok:
                        print(f'OK {label} portable-error')
                    else:
                        mismatches += 1
                        print(f'MISMATCH {label} portable rc={got.returncode} '
                              f'out={got.stdout[:80]!r} err={got.stderr[:160]!r}')
                    continue
                key = (locale, case['oracle'], case['before'], case['pipe'], case['payload'])
                if key not in oracle:
                    gargs = ['-r', '-s', case['oracle']]
                    if case['before']:
                        gargs = ['-b', *gargs]
                    genv = dict(base, LC_ALL=locale)
                    if case['pipe']:
                        cmd = ['/usr/bin/timeout', '-k', '1', str(args.timeout),
                               REFERENCE, *gargs]
                        gstdin = case['payload']
                    else:
                        cmd = ['/usr/bin/timeout', '-k', '1', str(args.timeout),
                               REFERENCE, *gargs, env['FILE']]
                        gstdin = None
                    ref = subprocess.run(cmd, input=gstdin, env=genv, capture_output=True,
                                         timeout=args.timeout + 5)
                    oracle[key] = ref
                ref = oracle[key]
                checks += 1
                if got.returncode in (124, 137) or ref.returncode in (124, 137):
                    timeouts += 1
                    print(f'TIMEOUT {label} builtin={got.returncode} gnu={ref.returncode}')
                elif (got.returncode, got.stdout) != (ref.returncode, ref.stdout):
                    mismatches += 1
                    print(f'MISMATCH {label} builtin={got.returncode} gnu={ref.returncode} '
                          f'out={got.stdout[:80]!r} gnu_out={ref.stdout[:80]!r} '
                          f'err={got.stderr[:120]!r}')
                else:
                    print(f'OK {label}')
    print(f'grok-tac-fix-hang: {checks} checks, {timeouts} timeouts, {mismatches} mismatches')
    if timeouts or mismatches:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
