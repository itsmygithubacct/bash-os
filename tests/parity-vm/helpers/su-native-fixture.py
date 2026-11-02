#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Private guest-root accounts and independent controls for SU credential tests.

The device replies are a client test double. Real Linux setgroups/setresgid/
setresuid calls and saved-ID reads establish the credential observations. A
failure is not silently treated as a rollback in the child that is exiting.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

CASE = Path('/tmp/parity-case')
HOME = Path('/tmp/parity-home')
HELPERS = Path('/opt/bashos-parity/harness/helpers')
VARIANTS = ('member', 'append-primary', 'primary-only', 'alternate', 'no-login')
FAULTS = ('none', 'setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid',
          'mismatch-getresuid', 'mismatch-getresgid')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def observer():
    spec = importlib.util.spec_from_file_location('su_native_guard', HELPERS / 'su-native-authority.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.guard()
    return module


PROBE = '''#!/usr/bin/python3
import json, os, sys
print('target=' + json.dumps({
    'uid': list(os.getresuid()), 'gid': list(os.getresgid()),
    'groups': os.getgroups(), 'cwd': os.getcwd(), 'argv': sys.argv,
    'env': {k: os.environ.get(k) for k in ('HOME', 'USER', 'LOGNAME', 'SHELL')}
}, sort_keys=True), flush=True)
sys.exit(7)
'''


# Independent Python control: the same synthetic wire contract, but no SU or
# credential library code. Invalid token/purpose/replay requests prove that the
# observer is selective. Only the one configured credential fault is injected.
CONTROL = '''import errno, fcntl, json, os, struct, sys
cfg = json.load(open('/tmp/parity-case/native-control.json'))
mint, consume = 0xc078ba08, 0x4078ba09
fd = os.open('/dev/bashos-auth', os.O_RDWR | os.O_CLOEXEC)
def payload(purpose=2, expiry=0, token=bytes(32)):
    return bytearray(struct.pack('<IIII32s64sII', cfg['uid'], cfg['gid'], purpose,
                     expiry, token, cfg['user'].encode().ljust(64, b'\\0'), 0, 0))
def denied(operation, data):
    try:
        fcntl.ioctl(fd, operation, data, True)
    except OSError as exc:
        assert exc.errno == errno.EPERM
    else:
        raise AssertionError('invalid authority request accepted')
denied(mint, payload(purpose=1, expiry=5))
buf = payload(expiry=5)
fcntl.ioctl(fd, mint, buf, True)
token = bytes(buf[16:48])
assert token == bytes(range(32, 64))
denied(consume, payload(token=bytes(32)))
denied(consume, payload(purpose=1, token=token))
valid = payload(token=token)
fcntl.ioctl(fd, consume, valid, True)
denied(consume, payload(token=token))
os.close(fd)
behavior = cfg.get('control_behavior', 'abort')
uid = gid = None
for name, operation in (
    ('setgroups', lambda: os.setgroups(cfg['groups'])),
    ('setresgid', lambda: os.setresgid(cfg['gid'], cfg['gid'], cfg['gid'])),
    ('setresuid', lambda: os.setresuid(cfg['uid'], cfg['uid'], cfg['uid'])),
    ('getresuid', os.getresuid), ('getresgid', os.getresgid)):
    try:
        value = operation()
        if name == 'getresuid': uid = value
        if name == 'getresgid': gid = value
    except OSError as exc:
        assert exc.errno == errno.EPERM
        if behavior != 'continue-after-fault':
            sys.exit(77)
if behavior == 'abort' and (uid != (cfg['uid'],) * 3 or gid != (cfg['gid'],) * 3):
    sys.exit(78)
env = {k: cfg[v] for k, v in (('HOME', 'home'), ('USER', 'user'),
                              ('LOGNAME', 'user'), ('SHELL', 'shell'))}
env['PATH'] = '/usr/bin:/bin'
if cfg['login']:
    os.chdir(cfg['home'])
argv = [('-' + os.path.basename(cfg['shell'])) if cfg['login'] else cfg['shell'],
        '-c', 'fixture-command']
os.execve(cfg['shell'], argv, env)
'''


def configuration(variant, fault, trace):
    alternate = variant == 'alternate'
    user = 'fixturealt' if alternate else 'fixturetarget'
    return {'uid': 3102 if alternate else 3101, 'gid': 3202 if alternate else 3201,
            'user': user, 'home': str(CASE / ('home-alt' if alternate else 'home-target')),
            'shell': str(CASE / ('alt-shell' if alternate else 'target-shell')),
            'groups': ([3202, 4102] if alternate else [3201] if variant == 'primary-only'
                       else [3201, 4101, 4102]),
            'login': variant != 'no-login', 'fault': fault, 'trace': str(HOME / trace)}


def run(cfg, program):
    config = CASE / ('native-control.json' if program[0] == '/usr/bin/python3' else 'native-candidate.json')
    config.write_text(json.dumps(cfg, sort_keys=True) + '\n')
    result = subprocess.run(['/usr/bin/python3', str(HELPERS / 'su-native-authority.py'),
                             str(config), *program], capture_output=True, text=True, timeout=30)
    stem = Path(cfg['trace']).stem
    (HOME / (stem + '.stdout')).write_text(result.stdout)
    (HOME / (stem + '.stderr')).write_text(result.stderr)
    rows = [json.loads(line) for line in Path(cfg['trace']).read_text().splitlines()]
    require(rows and rows[-1].get('syscall') == 'supervisor-end', 'observer did not finish')
    require(result.returncode != 125, 'observer could not complete')
    return result, rows


def identities(rows, required=True):
    opens = [r for r in rows if r.get('path') == '/dev/bashos-auth']
    if len(opens) != 1:
        require(not required, 'one owned authorization actor required')
        return None, None
    before = opens[0]['notifying']
    injected = [r for r in rows if 'injected_errno' in r or 'injected_readback' in r]
    state = injected[0]['notifying'] if injected else None
    return before, state


def same_credentials(left, right):
    return all(left[k] == right[k] for k in ('Uid', 'Gid', 'Groups'))


def fault_checks(cfg, rows):
    """Reject observer containment as evidence that the client aborted."""
    problems = []
    names = ['setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid']
    fault = cfg['fault']
    count = names.index(fault.removeprefix('mismatch-')) + 1
    if fault == 'mismatch-getresuid':
        count += 1  # The C helper reads both triples before comparing IDs.
    calls = [r for r in rows if r.get('syscall') in names]
    selected = [r for r in rows if r.get('reply_origin') == 'selected-fault']
    if [r['syscall'] for r in calls] != names[:count]:
        problems.append('client did not abort after the expected credential-call prefix')
    if len(selected) != 1 or selected[0]['syscall'] != fault.removeprefix('mismatch-'):
        problems.append('exactly one selected credential fault must occur')
    if any(r.get('reply_origin') == 'containment-guard' or r.get('invalid_order_or_arguments')
           or r.get('unapproved_target') for r in rows):
        problems.append('observer containment intervened after the selected fault')
    if any(r.get('phase') in ('target-exec', 'unapproved-exec') for r in rows):
        problems.append('client attempted target execution after the selected fault')
    exits = [r for r in rows if r.get('phase') == 'actor-exit']
    if len(exits) != 1 or exits[0].get('reply') != 'continue' or not exits[0].get('status'):
        problems.append('owned credential actor must reach an observed nonzero exit')
    for row in calls:
        if row not in selected and (row.get('real_kernel_call') is not True or row.get('reply') != 'continue'):
            problems.append('unselected credential call was replaced')
    return problems


def success_checks(cfg, result, rows):
    target = [r for r in rows if r.get('phase') == 'target-exec']
    probe = [json.loads(line[7:]) for line in result.stdout.splitlines() if line.startswith('target=')]
    problems = []
    def check(ok, message):
        if not ok:
            problems.append(message)
    check(rows[-1]['target_executed'] and len(target) == len(probe) == 1, 'one target must execute')
    if len(target) == 1:
        record = target[0]
        expected_argv = [('-' + Path(cfg['shell']).name) if cfg['login'] else cfg['shell'],
                         '-c', 'fixture-command']
        check(record['path'] == cfg['shell'] and record['argv'] == expected_argv,
              'shell and argv must come from selected account')
        env = dict(item.split('=', 1) for item in record['env'] if '=' in item)
        check(all(env.get(k) == cfg[v] for k, v in
                  (('HOME', 'home'), ('USER', 'user'), ('LOGNAME', 'user'), ('SHELL', 'shell'))),
              'account environment must match')
        check(record['cwd'] == (cfg['home'] if cfg['login'] else str(CASE)), 'working directory must match')
        check(record['notifying']['Uid'] == [cfg['uid']] * 4, 'kernel UID fields must match')
        check(record['notifying']['Gid'] == [cfg['gid']] * 4, 'kernel GID fields must match')
        check(record['notifying']['Groups'] == sorted(cfg['groups']), 'kernel groups must match')
    if len(probe) == 1:
        report = probe[0]
        check(report['uid'] == [cfg['uid']] * 3 and report['gid'] == [cfg['gid']] * 3,
              'target real/effective/saved IDs must match')
        check(report['groups'] == sorted(cfg['groups']), 'target groups must match')
        check(report['cwd'] == (cfg['home'] if cfg['login'] else str(CASE)), 'target cwd must match')
        check(all(report['env'].get(k) == cfg[v] for k, v in
                  (('HOME', 'home'), ('USER', 'user'), ('LOGNAME', 'user'), ('SHELL', 'shell'))),
              'target environment must match')
    changes = [r for r in rows if r.get('syscall') in ('setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid')]
    check([r['syscall'] for r in changes] == ['setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid'],
          'credential calls must be ordered')
    check(all(r.get('real_kernel_call') is True and r['reply'] == 'continue' for r in changes),
          'successful credentials must be real kernel calls')
    for name, key, expected in (('getresuid', 'Uid', cfg['uid']), ('getresgid', 'Gid', cfg['gid'])):
        completed = [r for r in rows if r.get('syscall') == 'kernel-identity-after-' + name]
        check(len(completed) == 1 and completed[0]['notifying'][key] == [expected] * 4,
              'live kernel credentials after continued ID read must match: ' + name)
    check(not any(r.get('invalid_order_or_arguments') or r.get('unapproved_target') for r in rows),
          'observer must accept candidate arguments')
    return problems


def setup(variant, fault):
    module = observer()
    parent = module.identity(os.getpid())
    passwd = ('root:x:0:0:Fixture root:/tmp/parity-home:/bin/bash\n'
              'fixturetarget:x:3101:3201:Fixture target:/tmp/parity-case/home-target:/tmp/parity-case/target-shell\n'
              'fixturealt:x:3102:3202:Fixture alternate:/tmp/parity-case/home-alt:/tmp/parity-case/alt-shell\n')
    primary_member = '' if variant in ('append-primary', 'primary-only') else 'fixturetarget'
    extras = '' if variant == 'primary-only' else 'fixturetarget'
    group = ('root:x:0:\n' + f'primary:x:3201:{primary_member}\n' +
             'alternate:x:3202:fixturealt\n' + f'staff:x:4101:{extras}\n' +
             f'wheel:x:4102:{extras + "," if extras else ""}fixturealt\n' +
             'unrelated:x:4900:someoneelse\n')
    for filename, content, target in (('passwd.fx', passwd, '/etc/passwd'), ('group.fx', group, '/etc/group')):
        source = CASE / filename
        source.write_text(content)
        source.chmod(0o644)
        subprocess.run(['/usr/bin/mount', '--bind', str(source), target], check=True, capture_output=True)
        require(Path(target).read_text() == content, 'private account bind differs')
    for name, uid, gid in (('home-target', 3101, 3201), ('home-alt', 3102, 3202)):
        directory = CASE / name
        directory.mkdir(mode=0o755)
        os.chown(directory, uid, gid)
    for name in ('target-shell', 'alt-shell'):
        path = CASE / name
        path.write_text(PROBE)
        path.chmod(0o755)
    control = CASE / 'native-control.py'
    control.write_text(CONTROL)
    cfg = configuration(variant, fault, 'native-control.jsonl')
    result, rows = run(cfg, ['/usr/bin/python3', str(control)])
    expected_status = 7 if fault == 'none' else 78 if fault.startswith('mismatch-') else 77
    require(result.returncode == expected_status, 'independent native control status differs: ' + str(result.returncode))
    require(result.stderr == '', 'independent native control has diagnostics: ' + result.stderr)
    ioctls = [r for r in rows if r.get('syscall') == 'ioctl' and r.get('modeled_authority')]
    require([r['valid'] for r in ioctls] == [False, True, False, False, True, False],
            'negative authority controls differ')
    before, state = identities(rows)
    require(same_credentials(parent, module.identity(os.getpid())), 'native control changed setup parent')
    if fault == 'none':
        require(not success_checks(cfg, result, rows), 'native success control does not meet independent checks')
    else:
        require(rows[-1]['injected'] and not rows[-1]['target_executed'] and state is not None,
                'fault control did not deny target execution')
        require(not fault_checks(cfg, rows), 'independent abort control fails the fault verdict')
        stage = ('setgroups', 'setresgid', 'setresuid', 'getresuid', 'getresgid').index(fault.removeprefix('mismatch-'))
        require(state['Uid'] == ([0] * 4 if stage <= 2 else [cfg['uid']] * 4), 'control UID observation differs')
        require(state['Gid'] == ([0] * 4 if stage <= 1 else [cfg['gid']] * 4), 'control GID observation differs')
        require(state['Groups'] == (before['Groups'] if stage == 0 else sorted(cfg['groups'])),
                'control group observation differs')
    negative = None
    if fault in ('setgroups', 'mismatch-getresuid'):
        bad = dict(cfg, trace=str(HOME / 'native-negative.jsonl'),
                   control_behavior='continue-after-fault' if fault == 'setgroups' else 'ignore-saved-id')
        bad_result, bad_rows = run(bad, ['/usr/bin/python3', str(control)])
        negative = fault_checks(bad, bad_rows)
        require(bad_rows[-1]['injected'] and negative and
                any(r.get('reply_origin') == 'containment-guard' for r in bad_rows),
                'fault verdict accepted a deliberately incorrect native control')
        record = {'behavior': bad['control_behavior'], 'status': bad_result.returncode,
                  'rejected': True, 'problems': negative}
        (HOME / 'native-negative-verdict.json').write_text(json.dumps(record, indent=2) + '\n')
    (HOME / 'native-setup.json').write_text(json.dumps({
        'variant': variant, 'fault': fault, 'control_status': result.returncode,
        'real_kernel_credentials': True, 'modeled_authority': True,
        'private_passwd': passwd, 'private_group': group,
        'parent_unchanged': True, 'child_at_fault': state,
        'child_unchanged': None if state is None else same_credentials(before, state),
        'negative_control_rejected': None if negative is None else bool(negative)
    }, indent=2, sort_keys=True) + '\n')


def candidate(binary, variant, fault):
    module = observer()
    require(binary == '/opt/bashos-parity/candidate', 'release candidate required')
    cfg = configuration(variant, fault, 'native-candidate.jsonl')
    # Only shell builtins occur in the parent. SU alone owns the credential
    # child; both the caller's actual /proc snapshots and external identity are
    # retained. No system account or system shell is selected by SU.
    driver = '''snapshot() {
  local line
  while IFS= read -r line; do
    case "$line" in Uid:*|Gid:*|Groups:*) printf '%s|%s\\n' "$1" "$line";; esac
  done < "/proc/$BASHPID/status"
}
snapshot before
export PHCLIB_PASSWD=/tmp/parity-case/passwd.fx
su MODE -c fixture-command USER
status=$?
snapshot after
printf 'su-status=%s\\n' "$status"
'''.replace('MODE', '--login' if cfg['login'] else '--no-login').replace('USER', shlex.quote(cfg['user']))
    before_parent = module.identity(os.getpid())
    result, rows = run(cfg, [binary, '--noprofile', '--norc', '-c', driver])
    snapshots = {'before': {}, 'after': {}}
    status = None
    for line in result.stdout.splitlines():
        if line.startswith('before|') or line.startswith('after|'):
            tag, rest = line.split('|', 1)
            key, values = rest.split(':', 1)
            require(key not in snapshots[tag], 'duplicate caller credential field')
            snapshots[tag][key] = [int(x) for x in values.split()]
        elif line.startswith('su-status='):
            require(status is None, 'duplicate SU status')
            status = int(line.split('=', 1)[1])
    parent_unchanged = (set(snapshots['before']) == {'Uid', 'Gid', 'Groups'} and
                        snapshots['before'] == snapshots['after'] and
                        same_credentials(before_parent, module.identity(os.getpid())))
    before, state = identities(rows, required=False)
    problems = [] if before is not None else ['SU did not open the modeled authority exactly once']
    if result.returncode != 0 or not parent_unchanged:
        problems.append('caller credentials or driver status changed')
    if fault == 'none':
        problems += success_checks(cfg, result, rows)
        if status != 7 or result.stderr:
            problems.append('SU must return exact target status without diagnostics')
        outcome = f'su-native {variant} real-ids=yes real-groups=yes saved-ids=yes account=yes caller-unchanged=yes'
    else:
        problems += fault_checks(cfg, rows)
        injected = rows[-1]['injected']
        denied = status is not None and status != 0 and not rows[-1]['target_executed']
        if not injected or not denied or state is None:
            problems.append('selected fault did not deny the transition')
        if 'privdrop:' not in result.stderr:
            problems.append('missing credential-failure diagnostic')
        exits = [r for r in rows if r.get('phase') == 'actor-exit']
        exit_identity = exits[0]['notifying'] if len(exits) == 1 else None
        child_unchanged = before is not None and exit_identity is not None and same_credentials(before, exit_identity)
        outcome = (f'su-native fault={fault} denied={"yes" if denied else "no"} '
                   f'caller-unchanged={"yes" if parent_unchanged else "no"} '
                   f'child-unchanged={"yes" if child_unchanged else "no"}')
    report = {'variant': variant, 'fault': fault, 'status': status,
              'caller': snapshots, 'caller_unchanged': parent_unchanged,
              'child_before': before, 'child_at_fault': state, 'problems': problems,
              'scope': 'SU client behavior; authority device and token replies are modeled'}
    if fault != 'none':
        report.update(child_at_exit=exit_identity, child_unchanged=child_unchanged,
                      target_not_executed=not any(r.get('phase') in ('target-exec', 'unapproved-exec') for r in rows),
                      literal_r3_result='PASS' if not problems and denied and parent_unchanged and child_unchanged else 'FAIL',
                      literal_r3_reason='No partial credential change is evaluated in the owned child at its observed exit; caller isolation is recorded separately.')
    (HOME / 'native-verdict.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    if problems:
        print('su-native contract mismatch: ' + '; '.join(problems))
        raise SystemExit(1)
    print(outcome)


def main():
    require(len(sys.argv) == 4, 'mode, variant, and fault required')
    action, variant, fault = sys.argv[1:]
    require(variant in VARIANTS and fault in FAULTS, 'unknown private fixture configuration')
    if action == 'setup':
        setup(variant, fault)
    else:
        candidate(action, variant, fault)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:
        print('su native fixture incomplete: ' + repr(exc), file=sys.stderr)
        raise SystemExit(125)
