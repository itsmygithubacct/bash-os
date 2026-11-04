#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Independent guest-only failure controls for ipset persistence."""
import os
import pathlib
import subprocess
import sys
import tempfile

IPS = '/usr/sbin/ipset'
IPT = '/usr/sbin/iptables'
SAVE = '/usr/sbin/iptables-save'
CAND = '/opt/bashos-parity/candidate'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp/parity-home'}


def run(argv, env=ENV):
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=20)
    return p.returncode, p.stdout, p.stderr


def must(argv):
    r = run(argv)
    if r[0] != 0:
        raise RuntimeError('setup %r failed: %r' % (argv, r))
    return r[1]


def fw(*args, env=ENV):
    return run([CAND, '--noprofile', '--norc', '-c',
                '[[ $(type -t fw) == builtin ]] || exit 97; fw -B iptables "$@"',
                'fw-test', *args], env)


def sets():
    return sorted(must([IPS, 'save']).splitlines())


def rules():
    return [x for x in must([SAVE]).splitlines() if not x.startswith('#')]


def require(cond, detail):
    if not cond:
        raise AssertionError(detail)


def setup():
    for chain in ('BASHFW_IN', 'BASHFW_OUT'):
        must([IPT, '-N', chain])
    for name, address in [('review_a', '192.0.2.10'), ('review_b', '198.51.100.10')]:
        must([IPS, 'create', name, 'hash:ip'])
        must([IPS, 'add', name, address])
    path = '/tmp/parity-case/review-fw-save.rules'
    result = fw('save', path)
    require(result[0] == 0, ('save', result))
    must([IPS, 'add', 'review_a', '192.0.2.11'])
    must([IPS, 'add', 'review_b', '198.51.100.11'])
    must([IPS, 'create', 'review_unrelated', 'hash:ip'])
    must([IPS, 'add', 'review_unrelated', '203.0.113.55'])
    return path


def malformed():
    path = setup()
    p = pathlib.Path(path)
    text = p.read_text()
    marker = '# fw ipset-save end\n'
    require(text.count(marker) == 1, 'missing save marker')
    p.write_text(text.replace(marker, 'add review_a not-an-address\n' + marker))
    before_sets, before_rules = sets(), rules()
    rc, out, err = fw('restore', path)
    require(rc != 0, ('malformed accepted', out, err))
    require(sets() == before_sets, ('sets changed on invalid input', before_sets, sets()))
    require(rules() == before_rules, 'rules changed on invalid input')


def malformed_markers():
    path = setup()
    p = pathlib.Path(path)
    text = p.read_text()
    marker = '# fw ipset-save begin\n'
    require(text.count(marker) == 1, 'missing save marker')
    p.write_text(text.replace(marker, marker + marker))
    before_sets, before_rules = sets(), rules()
    rc, out, err = fw('restore', path)
    require(rc != 0, ('duplicate marker accepted', out, err))
    require(sets() == before_sets, 'sets changed on malformed markers')
    require(rules() == before_rules, 'rules changed on malformed markers')


def embedded_nul():
    path = setup()
    p = pathlib.Path(path)
    data = p.read_bytes()
    require(data.count(b'*filter\n') == 1, 'missing filter table')
    p.write_bytes(data.replace(b'*filter\n', b'*filter\n# injected\x00tail\n', 1))
    before_sets, before_rules = sets(), rules()
    rc, out, err = fw('restore', path)
    require(rc != 0, ('NUL input accepted', out, err))
    require(sets() == before_sets, 'sets changed on NUL input')
    require(rules() == before_rules, 'rules changed on NUL input')


def oversized_line():
    path = setup()
    p = pathlib.Path(path)
    data = p.read_bytes()
    require(data.count(b'*filter\n') == 1, 'missing filter table')
    p.write_bytes(data.replace(b'*filter\n', b'*filter\n#' + b'x' * 70000 + b'\n', 1))
    before_sets, before_rules = sets(), rules()
    rc, out, err = fw('restore', path)
    require(rc != 0, ('oversized line accepted', out, err))
    require(sets() == before_sets, 'sets changed on oversized input')
    require(rules() == before_rules, 'rules changed on oversized input')


def swap_failure():
    path = setup()
    before_sets, before_rules = sets(), rules()
    with tempfile.TemporaryDirectory(prefix='review-fw-bin-', dir='/tmp/parity-home') as d:
        count = pathlib.Path(d) / 'swaps'
        wrapper = pathlib.Path(d) / 'ipset'
        wrapper.write_text('''#!/bin/sh
if [ "$1" = swap ]; then
 n=0; if [ -f "$REVIEW_SWAP_COUNT" ]; then read -r n < "$REVIEW_SWAP_COUNT"; fi
 n=$((n + 1)); printf '%s\\n' "$n" > "$REVIEW_SWAP_COUNT"
 if [ "$n" -eq 2 ]; then echo injected-second-swap >&2; exit 79; fi
fi
exec /usr/sbin/ipset "$@"
''')
        wrapper.chmod(0o755)
        env = dict(ENV, PATH=d + ':' + ENV['PATH'], REVIEW_SWAP_COUNT=str(count))
        rc, out, err = fw('restore', path, env=env)
        require(rc != 0 and 'injected-second-swap' in err, ('swap injection', rc, out, err))
        require(count.is_file() and int(count.read_text()) >= 3, 'rollback swap was not invoked')
    require(sets() == before_sets, ('failed swap changed sets', before_sets, sets()))
    require(rules() == before_rules, 'failed swap changed rules')


try:
    {'malformed': malformed, 'malformed-markers': malformed_markers, 'embedded-nul': embedded_nul, 'oversized-line': oversized_line, 'swap-failure': swap_failure}[sys.argv[1]]()
    print('staged ipset %s checks passed' % sys.argv[1])
except (AssertionError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
    print('FAIL: %s' % (exc,), file=sys.stderr)
    sys.exit(1)
