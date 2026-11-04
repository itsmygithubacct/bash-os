#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only PATH and real-kernel controls for fw save's ipset section."""
import hashlib
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('netlib', HERE/'mig-w1-netlib.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
BIN = '/usr/sbin/'
BEGIN = '# fw ipset-save begin\n'
END = '# fw ipset-save end\n'


def direct(*argv):
    result = L.run(list(argv))
    print('reference argv=%r result=%r' % (argv, result), file=sys.stderr, flush=True)
    return result


def must(label, result):
    if not L.check(label, result[0] == 0, repr(result)):
        raise RuntimeError(label + ' prerequisite/control failed')
    return result[1]


def fw(path, *args):
    result = L.cand('[[ $(type -t fw) == builtin ]] || exit 97; fw -B iptables "$@"',
                    *args, env={'PATH': path})
    print('candidate argv=%r result=%r' % (args, result), file=sys.stderr, flush=True)
    return result


def without_comments(text):
    return ''.join(line + '\n' for line in text.splitlines() if not line.startswith('#'))


def split_sections(saved, present):
    if not present:
        if BEGIN in saved or END in saved:
            raise ValueError('unexpected ipset section')
        return saved, None
    if saved.count(BEGIN) != 1 or saved.count(END) != 1:
        raise ValueError('missing or repeated section boundary')
    rules, section = saved.split(BEGIN)
    if rules and not rules.endswith('\n'):
        raise ValueError('section boundary is not a complete line')
    if not section.endswith(END):
        raise ValueError('section is not terminated at end of file')
    return rules, section[:-len(END)]


def snapshot_matches(saved, rules_reference, sets_reference):
    try:
        rules, sets = split_sections(saved, sets_reference is not None)
    except ValueError:
        return False
    return (without_comments(rules) == without_comments(rules_reference)
            and sets == sets_reference)


def comparator_canaries():
    rules = '*filter\nCOMMIT\n'
    sets = 'create sample hash:ip\n'
    good = rules + BEGIN + sets + END
    L.check('comparator accepts complete reference sections', snapshot_matches(good, rules, sets))
    L.check('comparator accepts absent section', snapshot_matches(rules, rules, None))
    malformed = {
        'truncated': good[:-len(END)],
        'duplicate': good + BEGIN + sets + END,
        'trailing data': good + 'extra\n',
        'injected rules': 'injected\n' + good,
        'injected set': rules + BEGIN + sets + 'add sample 192.0.2.1\n' + END,
        'reversed markers': rules + END + sets + BEGIN,
        'inline marker': rules.rstrip('\n') + BEGIN + sets + END,
    }
    for name, value in malformed.items():
        L.check('comparator rejects ' + name, not snapshot_matches(value, rules, sets))
    L.check('comparator rejects section when absent', not snapshot_matches(good, rules, None))


def verify_rules(saved):
    reference = must('real iptables-save succeeds', direct(BIN+'iptables-save'))
    L.check('rules match real iptables-save', without_comments(saved) == without_comments(reference),
            'saved=%r reference=%r' % (saved, reference))
    L.check('deny rule retained', '-A BASHFW_IN -s 198.51.100.0/24 -j DROP\n' in saved, saved)
    L.check('allow rule retained', '-A BASHFW_IN -s 192.0.2.10/32 -p tcp -m tcp --dport 22 -j ACCEPT\n' in saved, saved)
    L.check('unrequested deny absent', '-A BASHFW_IN -s 203.0.113.99/32 -j DROP\n' not in saved, saved)


def read_save(path, output, present):
    must('candidate save', fw(path, 'save', output))
    text = pathlib.Path(output).read_text()
    rules, sets = split_sections(text, present)
    verify_rules(rules)
    reference = must('real ipset save for exact section comparison', direct(BIN+'ipset', 'save')) if present else None
    L.check('complete ipset section matches real reference', sets == reference, repr((sets, reference)))
    print('candidate saved snapshot=%r' % text, file=sys.stderr, flush=True)
    return text


def scenario(which):
    with tempfile.TemporaryDirectory(prefix='save-path-', dir='/tmp/parity-case') as scratch:
        for name in ('iptables', 'ip6tables', 'iptables-save') + (('ipset',) if which == 'present' else ()):
            target = pathlib.Path(BIN+name)
            link = pathlib.Path(scratch)/name
            if not target.is_file() or not os.access(target, os.X_OK):
                raise RuntimeError('missing real executable: ' + str(target))
            link.symlink_to(target)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            L.check('real pinned executable ' + name, os.path.samefile(link, target), str(link))
            print('reference tool=%s realpath=%s sha256=%s' % (name, target.resolve(), digest), file=sys.stderr, flush=True)
        ipset_path = shutil.which('ipset', path=scratch)
        L.check('reference PATH ipset availability', bool(ipset_path) == (which == 'present'), repr(ipset_path))
        probe = L.cand('type -P ipset', env={'PATH': scratch})
        L.check('candidate PATH ipset availability', (probe[0] == 0) == (which == 'present'), repr(probe))
        if which == 'present':
            L.check('candidate finds real ipset', probe[1].strip() == str(pathlib.Path(scratch)/'ipset'), repr(probe))
        else:
            L.check('candidate finds no ipset output', probe[1] == '', repr(probe))

        initial = must('reference ipset save', direct(BIN+'ipset', 'save'))
        if not L.check('fresh namespace has no ipsets', initial == '', repr(initial)):
            raise RuntimeError('kernel set precondition not empty')
        must('candidate reset', fw(scratch, 'reset'))
        must('candidate deny', fw(scratch, 'deny', '198.51.100.0/24'))
        must('candidate allow', fw(scratch, 'allow', '192.0.2.10', '-p', 'tcp', '-d', '22'))
        output = '/tmp/parity-case/save-presence.rules'
        saved = read_save(scratch, output, which == 'present')
        if which == 'absent':
            L.check('no ipset markers when absent', BEGIN not in saved and END not in saved, saved)
            return
        L.check('empty inventory produces exact empty section', saved.count(BEGIN) == 1 and saved.count(END) == 1 and saved.endswith(BEGIN+END), saved)
        must('reference create empty set', direct(BIN+'ipset', 'create', 'presence_set', 'hash:ip'))
        missing = direct(BIN+'ipset', 'test', 'presence_set', '192.0.2.99')
        L.check('empty set lacks member', missing[0] == 1, repr(missing))
        reference = must('reference save empty set', direct(BIN+'ipset', 'save'))
        saved = read_save(scratch, output, which == 'present')
        L.check('empty set snapshot matches reference bytes', saved.endswith(BEGIN+reference+END), saved)
        must('reference add member', direct(BIN+'ipset', 'add', 'presence_set', '192.0.2.10'))
        must('reference add second member', direct(BIN+'ipset', 'add', 'presence_set', '192.0.2.11'))
        present = direct(BIN+'ipset', 'test', 'presence_set', '192.0.2.10')
        present2 = direct(BIN+'ipset', 'test', 'presence_set', '192.0.2.11')
        missing = direct(BIN+'ipset', 'test', 'presence_set', '192.0.2.99')
        L.check('reference positive and negative membership', present[0] == 0 and present2[0] == 0 and missing[0] == 1, repr((present, present2, missing)))
        reference = must('reference save populated set', direct(BIN+'ipset', 'save'))
        saved = read_save(scratch, output, which == 'present')
        L.check('populated snapshot matches reference bytes', saved.endswith(BEGIN+reference+END), saved)


if __name__ == '__main__':
    mode = sys.argv[1]
    try:
        if mode not in ('present', 'absent'):
            raise ValueError('unknown mode')
        comparator_canaries()
        scenario(mode)
    except Exception as exc:
        L.check('fixture completed', False, repr(exc))
    sys.exit(L.finish('save-ipset-section-'+mode))
