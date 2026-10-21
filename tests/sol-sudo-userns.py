#!/usr/bin/env python3
"""Live root-route sudo/doas checks inside a private user and mount namespace.

The checker re-executes itself under unshare(1) as namespace root, with the
caller's subordinate uid/gid range mapped in. Private passwd, group and profile
files are bind-mounted over /etc inside that mount namespace only, so the
native shell's production code performs real setgroups/setresgid/setresuid,
no_new_privs, signal/FD cleanup, exec and wait against private account data.
Nothing on the host changes, and no host account or policy file is written.
Optionally runs tests/final-smoke.py's accounts section in the same setup,
with its root transitions required rather than skipped."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--shell', type=Path, required=True)
p.add_argument('--final-smoke', action='store_true', help='also run tests/final-smoke.py accounts in the namespace')
p.add_argument('--report', type=Path)
p.add_argument('--inside', help=argparse.SUPPRESS)
a = p.parse_args()


def subordinate(path):
    names = {str(os.getuid())}
    try:
        import pwd
        names.add(pwd.getpwuid(os.getuid()).pw_name)
    except KeyError:
        pass
    for line in Path(path).read_text().splitlines():
        fields = line.split(':')
        if len(fields) == 3 and fields[0] in names:
            return int(fields[1]), int(fields[2])
    raise SystemExit(f'no subordinate range for this user in {path}')


if not a.inside:
    uid_start, uid_count = subordinate('/etc/subuid')
    gid_start, gid_count = subordinate('/etc/subgid')
    count = min(uid_count, gid_count, 65535)
    assert count >= 4545 + 1, 'subordinate range too small for the fixture ids'
    cmd = ['unshare', '--user', '--map-root-user', f'--map-users=1:{uid_start}:{count}',
           f'--map-groups=1:{gid_start}:{count}', '--mount', '--propagation', 'private',
           sys.executable, '-I', str(Path(__file__).resolve()), '--shell', str(a.shell.resolve()),
           '--inside', str(count)]
    if a.final_smoke:
        cmd.append('--final-smoke')
    if a.report:
        cmd += ['--report', str(a.report.resolve())]
    proc = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1])
    raise SystemExit(proc.returncode)

mapped = int(a.inside)
assert os.geteuid() == 0 and os.getuid() == 0, 'expected namespace root'
assert Path('/proc/self/setgroups').read_text().strip() == 'allow'
assert not Path('/dev/bashos-auth').exists(), 'the live authority would change the routes under test'
shell = str(a.shell)
cases = []


def case(name, ok, detail=''):
    cases.append(dict(case=name, status='pass' if ok else 'fail', detail='' if ok else detail))
    print(('PASS ' if ok else 'FAIL ') + name + ('' if ok else ': ' + detail), flush=True)


# Under /tmp so the mapped target ids can traverse to their home.
with tempfile.TemporaryDirectory(prefix='sol-sudo-userns-', dir='/tmp') as tmp:
    tmp = Path(tmp)
    os.chmod(tmp, 0o755)
    home = tmp / 'home'
    home.mkdir(mode=0o755)
    os.chown(home, 4242, 4343)
    unmapped = mapped + 10
    files = {
        'passwd': (f'root:x:0:0:root:/root:/bin/sh\n'
                   f'target:x:4242:4343:Target:{home}:/bin/sh\n'
                   f'nohome:x:4300:4300:No home:{tmp}/missing:/bin/sh\n'
                   f'unmapped:x:{unmapped}:{unmapped}:Unmapped:/:/bin/sh\n'
                   f'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'),
        'group': ('root:x:0:\n'
                  'target:x:4343:\n'
                  'extra:x:4444:other,target\n'
                  'chosen:x:4545:target\n'
                  'nogroup:x:65534:\n'),
        'profile': '',
    }
    for name, text in files.items():
        (tmp / name).write_text(text)
        os.chmod(tmp / name, 0o644)
        subprocess.run(['mount', '--bind', str(tmp / name), f'/etc/{name}'], check=True)
    assert Path('/etc/passwd').read_text() == files['passwd']

    editor = tmp / 'editor'
    editor.write_text('#!/bin/sh\n[ "$1" = --flag ] || exit 7\nshift\nfor f; do printf +edited >> "$f"; done\n')
    editor.chmod(0o755)
    edited = tmp / 'edited'
    edited.write_text('old')

    def run(script, extra=None, timeout=60):
        env = {'LC_ALL': 'C', 'HOME': '/root', 'USER': 'spoofed', 'TERM': 'dumb',
               'BASH_ENV': '/nonexistent/bash_env', 'LD_LIBRARY_PATH': '/nonexistent', **(extra or {})}
        return subprocess.run([shell, '--noprofile', '--norc', '-c', 'PATH=\n' + script], env=env,
                              capture_output=True, timeout=timeout)

    def expect(name, script, stdout=None, rc=0, extra=None, check=None):
        proc = run(script, extra)
        out = proc.stdout.decode(errors='replace')
        ok = proc.returncode == rc and (stdout is None or out == stdout) and (check is None or check(out, proc))
        case(name, ok, f'rc={proc.returncode} out={out!r} err={proc.stderr.decode(errors="replace")!r}')

    expect('ids: child drops, shell stays root',
           'sudo -u target /usr/bin/id -u; sudo -u target /usr/bin/id -g; /usr/bin/id -u',
           '4242\n4343\n0\n')
    expect('groups: passwd primary plus memberships',
           'sudo -u target /usr/bin/id -G', check=lambda out, _: sorted(out.split()) == ['4343', '4444', '4545'])
    expect('groups: -g picks the primary group, passwd group stays supplementary',
           'sudo -u target -g chosen /usr/bin/id -g; sudo -utarget -gchosen /usr/bin/id -G',
           check=lambda out, _: out.split('\n')[0] == '4545' and sorted(out.split('\n')[1].split()) == ['4343', '4444', '4545'])
    expect('groups: -g without -u runs as the invoking user',
           'sudo -g chosen /usr/bin/id -u; sudo -g "#4444" /usr/bin/id -g', '0\n4444\n')
    expect('bundled -nu and #uid', 'sudo -nu target /usr/bin/id -u; sudo -u "#4242" /usr/bin/id -un', '4242\ntarget\n')

    def env_ok(out, _):
        env = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
        names = [line.split('=', 1)[0] for line in out.splitlines()]
        return (len(names) == len(set(names)) and env.get('USER') == 'target' and env.get('LOGNAME') == 'target'
                and env.get('HOME') == '/override' and env.get('SHELL') == '/bin/sh'
                and env.get('PATH') == '/bin:/bash-os:/usr/bin' and env.get('SUDO_USER') == 'root'
                and env.get('SUDO_UID') == '0' and env.get('SUDO_GID') == '0' and env.get('A') == '1'
                and env.get('SUDO_COMMAND') == '/usr/bin/env' and env.get('TERM') == 'dumb'
                and not any(n in env for n in ['BASH_ENV', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'PS4', 'SHELLOPTS']))
    expect('environment: scrubbed, account-derived SUDO_USER, one value per name',
           'export LD_PRELOAD=/nonexistent.so; sudo -u target A=0 A=1 HOME=/override LD_PRELOAD=x PS4=x SHELLOPTS=xtrace /usr/bin/env',
           check=env_ok)
    expect('no_new_privs in the child only',
           'sudo -u target /bin/grep NoNewPrivs /proc/self/status; /bin/grep NoNewPrivs /proc/$$/status',
           'NoNewPrivs:\t1\nNoNewPrivs:\t0\n')
    expect('descriptors closed in the child, kept in the shell',
           'exec 200</dev/null 201>/dev/null; sudo -u target /bin/sh -c \'/bin/ls /proc/$$/fd\'; [[ -r /proc/$$/fd/200 && -w /proc/$$/fd/201 ]] && echo kept',
           '0\n1\n2\nkept\n')

    def signals_ok(out, _):
        rows = dict(line.split(':\t') for line in out.splitlines())
        return int(rows['SigIgn'], 16) & (1 << 14) == 0 and int(rows['SigBlk'], 16) == 0 and int(rows['SigIgn'], 16) & (1 << 1) == 0
    expect('ignored/blocked signals reset in the child',
           "trap '' TERM INT; sudo -u target /bin/grep -E '^Sig(Ign|Blk)' /proc/self/status", check=signals_ok)
    expect('status: exit, signal, not found, not executable',
           'sudo -u target /bin/sh -c "exit 23"; echo $?; sudo -u target /bin/sh -c "kill -TERM \\$\\$"; echo $?; '
           'sudo -u target /nonexistent/cmd 2>/dev/null; echo $?; sudo -u target /etc/passwd 2>/dev/null; echo $?; '
           'sudo -u target nonexistent-anywhere 2>/dev/null; echo $?', '23\n143\n127\n126\n127\n')
    expect('literal argv', 'sudo -u target /usr/bin/printf "[%s]" "a b" "" "\\$(no)" "\'"', "[a b][][$(no)][']")
    expect('secure path resolution of a relative command', 'sudo -u target id -u', '4242\n')
    expect('-i: login shell named -sh in the target home',
           "printf 'echo \"$0\"; pwd\\n' | sudo -iu target", f'-sh\n{home}\n')
    # $ reaches the login shell, so $0 is that shell's argv0 (-sh), not the
    # later word "named". The command still runs there, in the target home.
    expect('-i with a command runs it through the login shell',
           'sudo -i -u target /bin/sh -c \'echo "$0"; pwd\' named', f'-sh\n{home}\n')
    expect('-i with a missing home warns and still starts',
           "printf 'pwd\\n' | sudo -iu nohome", check=lambda out, proc: out.strip() != '' and b'unable to change directory' in proc.stderr)
    expect('-s runs the target shell in place', "cd /tmp; printf 'pwd; echo \"$0\"\\n' | sudo -su target", '/tmp\n/bin/sh\n')
    expect('-k/-K/-v need no credential as root', 'sudo -k && sudo -K && sudo -v && sudo -k -u target /usr/bin/id -u', '4242\n')
    expect('usage: exclusive modes and -K/-v with a command',
           'sudo -s -i; a=$?; sudo -K /bin/true; b=$?; sudo -v /bin/true; c=$?; sudo -iE; d=$?; echo $a$b$c$d', '2222\n')
    expect('lookup failures stop before any child',
           'sudo -u missing /bin/true; a=$?; sudo -u "#4294967296" /bin/true; b=$?; sudo -u target -g nosuch /bin/true; c=$?; echo $a$b$c',
           '111\n')
    expect('a credential the kernel refuses fails closed with 126',
           'sudo -u unmapped /usr/bin/id -u; echo $?', check=lambda out, proc: out == '126\n' and b'privdrop' in proc.stderr)
    expect('doas root route: same drop, no SUDO_COMMAND',
           'doas -u target /usr/bin/id -u; doas -u target /usr/bin/env', check=lambda out, _: out.startswith('4242\n') and 'SUDO_COMMAND=' not in out and 'USER=target' in out)
    expect('root sudoedit runs the split editor on the file',
           f'sudo -e {edited}; echo $?; /bin/cat {edited}', '0\nold+edited', extra={'SUDO_EDITOR': f'{editor} --flag'})
    (tmp / 'sol-sudo-editor').write_text('#!/bin/sh\n[ "$1" = --flag ] || exit 7\nshift\n'
                                         'for f; do printf "+$EDIT_MARK" >> "$f"; done\n')
    (tmp / 'sol-sudo-editor').chmod(0o755)
    expect('root sudoedit finds the editor on a freshly exported PATH and passes fresh exports',
           f'export PATH={tmp} SUDO_EDITOR="sol-sudo-editor --flag" EDIT_MARK=fresh; sudo -e {edited}; echo $?; /bin/cat {edited}',
           '0\nold+edited+fresh')
    expect('repeated calls keep background statuses and the CHLD trap',
           '''trap ':' CHLD; saved=$(trap -p CHLD)
for ((i=0;i<200;i++)); do
  (exit 41) & bg=$!
  sudo -u target /bin/sh -c 'exit 37'; [[ $? == 37 ]] || exit 90
  wait "$bg"; [[ $? == 41 ]] || exit 91
  [[ $(trap -p CHLD) == "$saved" ]] || exit 92
done; echo done''', 'done\n')

    if a.final_smoke:
        env = {**os.environ, 'BASHOS_REQUIRE_ROOT_TRANSITIONS': '1', 'PATH': '/usr/bin:/bin'}
        proc = subprocess.run([sys.executable, 'tests/final-smoke.py', shell, 'accounts'], env=env,
                              capture_output=True, timeout=600)
        out = proc.stdout.decode(errors='replace') + proc.stderr.decode(errors='replace')
        case('final-smoke accounts with required root transitions',
             proc.returncode == 0 and 'SKIP root doas/sudo' not in out, out[-4000:])
        cases[-1]['output_tail'] = out[-4000:]

failed = [c for c in cases if c['status'] != 'pass']
if a.report:
    a.report.write_text(json.dumps(dict(cases=cases, failed=len(failed), total=len(cases), mapped_ids=mapped), indent=2) + '\n')
print(f'sol-sudo userns: {len(cases) - len(failed)}/{len(cases)} passed; namespace root over private account files; '
      'no live /dev/bashos-auth')
raise SystemExit(1 if failed else 0)
