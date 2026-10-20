#!/usr/bin/env python3
"""payload installer-boundary integration checks. Does not compile.

Every case runs the real `payload` builtin against a private repo INDEX, a
private install root and a recording fake bl-pkg.sh that receives exactly the
argv production builds ($BASH INSTALLER --internal --root ...). The fake keeps
its own install state, so install -> list -> info -> remove round-trips
through the transaction ids it wrote. Nothing reads or writes the host's
/root/loadables, /var/lib/bl-pkg or /bash-os.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', nargs='?', default='out/bash-opus-payload')
parser.add_argument('--module', type=Path, help='enable -f this payload.so first')
parser.add_argument('--asan-runtime', type=Path)
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
prefix = ('enable -f ' + shlex.quote(str(args.module.resolve())) + ' payload || exit 99\n'
          if args.module else '')
checks = 0
failures = []

FAKE = r'''# fake bl-pkg.sh: record argv, then emulate install/rollback privately.
log=${FAKE_LOG:?}
n=0
while [[ -e $log/call.$n ]]; do n=$((n + 1)); done
printf '%s\0' "$BASH" "$0" "$@" > "$log/call.$n"
printf '%s' "${FAKE_MARK-unset}" > "$log/mark.$n"
mode=${FAKE_MODE:-ok}
case $mode in
  fail:*) echo "helper: failing with ${mode#fail:}" >&2; exit "${mode#fail:}" ;;
  signal) kill -TERM $$ ;;
  failtxn:*) [[ $* == *"${mode#failtxn:}"* ]] && exit 9 ;;
esac
[[ $1 == --internal && $2 == --root ]] || exit 64
state=$3/var/lib/bl-pkg/installed
shift 3
case $1 in
  --repo)
    [[ $3 == --allow-unsigned && $4 == install && -r $2/INDEX ]] || exit 64
    shift 4
    for name; do
      printf 'txn=txn-%s-%d\nversion=fake\n' "$name" "$n" > "$state/$name"
      echo "helper: installed $name"
    done ;;
  rollback)
    [[ $# == 2 ]] || exit 64
    for f in "$state"/*; do
      while IFS= read -r line; do
        [[ $line == txn=* ]] || continue
        line=${line%$'\r'}
        if [[ $line == "txn=$2" ]]; then
          PATH=/usr/bin:/bin rm -f -- "$f"
          echo "helper: rolled back $2"
          exit 0
        fi
        break
      done < "$f"
    done
    exit 65 ;;
  *) exit 64 ;;
esac
'''

GOOD_INDEX = '''# bashy.box payload index (fixture)

blpkg-v1 name=bun version=1.2.3 arch=x86_64 type=payload provides=bin/bun
blpkg-v1\tname=python3 version=3.13.1 arch=x86_64 provides=bin/python3,bin/pip3
other-format name=ignored version=9
blpkg-v1 name=gcc version=14.2 arch=x86_64 type=toolchain provides=bin/gcc
blpkg-v1 name=rust
'''


def row(status, name, ver, prov):
    return '  %-10s  %-18s  %-12s  %s\n' % (status, name, ver, prov)


with tempfile.TemporaryDirectory(prefix='opus-payload-') as directory:
    top = Path(directory)
    # Paths deliberately carry spaces, quotes and command-substitution text.
    repo = top / "re po 'q' $(touch PWNED)"
    root = top / 'ro"ot `touch PWNED`'
    log = top / 'log'
    helper = top / 'bl-pkg.sh'
    for d in (repo, root / 'var/lib/bl-pkg/installed', log):
        d.mkdir(parents=True)
    state = root / 'var/lib/bl-pkg/installed'
    helper.write_text(FAKE)
    helper.chmod(0o644)             # production ships it non-executable too
    base_env = {'LC_ALL': 'C', 'HOME': str(top), 'PATH': '',
                'PAYLOAD_REPO': str(repo), 'PAYLOAD_ROOT': str(root),
                'PAYLOAD_INSTALLER': str(helper), 'FAKE_LOG': str(log)}
    if args.asan_runtime:
        base_env.update(LD_PRELOAD=str(args.asan_runtime.resolve()),
                        ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                        UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')

    def reset(index=GOOD_INDEX, installed=None):
        (repo / 'INDEX').write_text(index)
        for f in state.iterdir():
            f.unlink()
        for f in log.iterdir():
            f.unlink()
        for name, body in (installed or {}).items():
            (state / name).write_text(body)

    def calls():
        out, n = [], 0
        while (log / f'call.{n}').exists():
            argv = (log / f'call.{n}').read_bytes().split(b'\0')[:-1]
            out.append([a.decode() for a in argv])
            n += 1
        return out

    def run(script, env=None, unset=(), pin=False):
        e = dict(base_env, **(env or {}))
        for k in unset:
            e.pop(k, None)
        cpu = min(os.sched_getaffinity(0))
        return subprocess.run([binary, '--norc', '--noprofile', '-c', prefix + script],
                              capture_output=True, env=e, timeout=30, text=True,
                              errors='backslashreplace',
                              preexec_fn=(lambda: os.sched_setaffinity(0, {cpu})) if pin else None)

    def check(label, script, status=0, stdout=None, stderr_has=(), stderr_empty=None,
              ncalls=None, argvs=None, env=None, unset=(), extra=None, pin=False):
        global checks
        r = run(script, env, unset, pin)
        got = calls()
        problems = []
        if r.returncode != status:
            problems.append(f'status {r.returncode} != {status}')
        if stdout is not None and r.stdout != stdout:
            problems.append(f'stdout {r.stdout!r} != {stdout!r}')
        for s in stderr_has:
            if s not in r.stderr:
                problems.append(f'stderr lacks {s!r}')
        if stderr_empty is None:
            stderr_empty = status == 0 and not stderr_has
        if stderr_empty and r.stderr:
            problems.append(f'unexpected stderr {r.stderr!r}')
        if 'runtime error:' in r.stderr or 'AddressSanitizer' in r.stderr:
            problems.append('sanitizer report')
        if ncalls is not None and len(got) != ncalls:
            problems.append(f'{len(got)} helper calls != {ncalls}: {got}')
        if argvs is not None and got != argvs:
            problems.append(f'helper argv {got} != {argvs}')
        if extra:
            msg = extra(r, got)
            if msg:
                problems.append(msg)
        if (top / 'PWNED').exists() or (Path.cwd() / 'PWNED').exists():
            problems.append('injection string was executed')
        checks += 1
        if problems:
            failures.append((label, problems, r.stdout, r.stderr))
        return r

    INSTALL = [binary, str(helper), '--internal', '--root', str(root), '--repo',
               str(repo), '--allow-unsigned', 'install']
    ROLLBACK = [binary, str(helper), '--internal', '--root', str(root), 'rollback']
    header = f'payload: repo {repo}\n\n' + row('STATUS', 'NAME', 'VERSION', 'PROVIDES')
    full = [('bun', '1.2.3', 'bin/bun'), ('python3', '3.13.1', 'bin/python3,bin/pip3'),
            ('gcc', '14.2', 'bin/gcc'), ('rust', '-', '')]

    # --- read-only verbs over a parsed INDEX and install state ---------------
    reset(installed={'gcc': 'version=14.2\ntxn=T-gcc-7\n'})
    check('builtin with empty PATH', 'type -t payload', stdout='builtin\n')
    rows = ''.join(row('installed' if n == 'gcc' else 'available', n, v, p)
                   for n, v, p in full)
    check('list', 'payload list', stdout=header + rows +
          '\npayload: 4 available, 1 installed\n', ncalls=0)
    check('bare payload == list', 'payload', stdout=header + rows +
          '\npayload: 4 available, 1 installed\n')
    check('porcelain', 'payload list --porcelain', stdout=''.join(
        '%s\t%s\t%s\t%s\n' % ('installed' if n == 'gcc' else 'available', n, v, p)
        for n, v, p in full))
    check('-p --installed', 'payload list -p --installed',
          stdout='installed\tgcc\t14.2\tbin/gcc\n')
    check('installed verb', 'payload installed', stdout=header +
          row('installed', 'gcc', '14.2', 'bin/gcc') +
          '\npayload: 4 available, 1 installed (showing installed)\n')
    check('available filter', 'payload list --available', stdout=header +
          ''.join(row('available', n, v, p) for n, v, p in full if n != 'gcc') +
          '\npayload: 4 available, 1 installed (showing not-installed)\n')
    check('unknown list option', 'payload list --bogus', status=2,
          stderr_has=["unknown option '--bogus'"])
    check('installed takes no argument', 'payload installed x', status=2,
          stderr_has=['unexpected argument'])
    check('info installed with txn', 'payload info gcc', stdout=(
        'name:      gcc\nversion:   14.2\narch:      x86_64\ntype:      toolchain\n'
        'provides:  bin/gcc\nstatus:    installed (txn T-gcc-7)\n'))
    check('info default type, no provides', 'payload info rust', stdout=(
        'name:      rust\nversion:   -\narch:      -\ntype:      payload\n'
        'status:    available (not installed)\n'))
    check('info tab-separated record', 'payload info python3',
          extra=lambda r, g: None if 'provides:  bin/python3,bin/pip3\n' in r.stdout
          else 'tab record not parsed')
    check('info missing package', 'payload info nope', status=1,
          stderr_has=["no payload named 'nope'"])
    check('info comment/other-format not records', 'payload info ignored', status=1,
          stderr_has=["no payload named 'ignored'"])
    check('info requires NAME', 'payload info', status=2, stderr_has=['NAME is required'])
    check('info extra argument', 'payload info gcc bun', status=2,
          stderr_has=["unexpected argument 'bun'"])
    check('info traversal name', 'payload info ../../etc/passwd', status=2,
          stderr_has=['invalid payload name'])
    check('unknown verb', 'payload frobnicate', status=2, stderr_has=['unknown verb'])
    check('help', 'payload help', extra=lambda r, g: None if 'payload install NAME'
          in r.stdout else 'help text missing')
    reset(installed={'gcc': 'version=14.2\n'})
    check('info installed without txn', 'payload info gcc',
          extra=lambda r, g: None if r.stdout.endswith('status:    installed\n')
          else 'status line wrong')

    # --- repo/env resolution ---------------------------------------------
    alt = top / 'alt repo'
    alt.mkdir()
    (alt / 'INDEX').write_text('blpkg-v1 name=only version=1\n')
    check('BASHPKG_LOADABLES_DATADIR fallback', 'payload list -p',
          env={'BASHPKG_LOADABLES_DATADIR': str(alt)}, unset=('PAYLOAD_REPO',),
          stdout='available\tonly\t1\t\n')
    check('unexported shell variable fallback',
          f'BASHPKG_LOADABLES_DATADIR={shlex.quote(str(alt))}; payload list -p',
          unset=('PAYLOAD_REPO',), stdout='available\tonly\t1\t\n')
    check('PAYLOAD_REPO wins', 'payload list -p',
          env={'BASHPKG_LOADABLES_DATADIR': str(alt)}, stdout=''.join(
              '%s\t%s\t%s\t%s\n' % ('installed' if n == 'gcc' else 'available', n, v, p)
              for n, v, p in full))
    check('no repo staged', 'payload list', status=1,
          env={'PAYLOAD_REPO': str(top / 'absent')},
          extra=lambda r, g: None if 'no payload repo staged' in r.stdout else 'no hint')

    # --- malformed INDEX --------------------------------------------------
    long_tail = 'x' * (8191 - len('blpkg-v1 name=long provides=')) + \
        'blpkg-v1 name=smuggled version=6\n'
    malformed = ('blpkg-v1 name=ok version=1\n'
                 'blpkg-v1 name=../escape version=1\n'
                 'blpkg-v1 name=-rf version=1\n'
                 'blpkg-v1 version=1 arch=x86_64\n'
                 'blpkg-v1 name=' + 'n' * 300 + ' version=1\n'
                 'blpkg-v1 name=bigver version=' + 'v' * 300 + '\n'
                 'blpkg-v1 name=long provides=' + long_tail +
                 'blpkg-v1 name=last version=2')           # no final newline
    reset(index=malformed)
    check('malformed records skipped with warning', 'payload list -p',
          stdout='available\tok\t1\t\navailable\tlast\t2\t\n',
          stderr_has=['skipped 6 malformed records'], stderr_empty=False)
    check('overlong line tail is not a record', 'payload info smuggled', status=1,
          stderr_has=["no payload named 'smuggled'"])
    check('install refuses skipped record', 'payload install bigver', status=1,
          stderr_has=["no payload named 'bigver'"], ncalls=0)
    (repo / 'INDEX').unlink()
    (repo / 'INDEX').mkdir()
    check('INDEX is a directory', 'payload list', status=1,
          stderr_has=['read error'], ncalls=0)
    check('install with unreadable INDEX', 'payload install ok', status=1,
          stderr_has=['read error'], ncalls=0)
    (repo / 'INDEX').rmdir()
    check('install with no INDEX', 'payload install ok', status=1,
          stderr_has=['no payload repo staged'], ncalls=0)

    reset(index='blpkg-v1 name=bun\x00hidden version=1\n'
                'blpkg-v1 name=rust version=2\n')
    check('NUL record rejected without hiding the next record', 'payload list -p',
          stdout='available\trust\t2\t\n', stderr_has=['skipped 1 malformed record'])
    check('install refuses NUL-truncated name', 'payload install bun', status=1,
          stderr_has=["no payload named 'bun'"], ncalls=0)

    # --- install through the helper boundary -------------------------------
    reset()
    check('install multiple names', 'payload install bun gcc',
          stdout='helper: installed bun\nhelper: installed gcc\n',
          argvs=[INSTALL + ['bun', 'gcc']])
    check('installed state now visible', 'payload list -p --installed',
          stdout='installed\tbun\t1.2.3\tbin/bun\ninstalled\tgcc\t14.2\tbin/gcc\n')
    check('info reports helper txn', 'payload info bun',
          extra=lambda r, g: None if 'installed (txn txn-bun-0)' in r.stdout else r.stdout)
    reset()
    check('one missing package blocks the whole install',
          'payload install bun nope gcc also-nope', status=1,
          stderr_has=["no payload named 'nope'", "no payload named 'also-nope'"], ncalls=0)
    check('install needs a NAME', 'payload install', status=2, ncalls=0,
          stderr_has=['at least one NAME'])
    for bad in ('--root=/', '-x', 'a b', 'a;b', '$(touch PWNED)', '../etc', '.hidden',
                '', 'bun/../gcc', 'tab\tname', 'nl\nname'):
        check(f'install rejects {bad!r}', f'payload install bun {shlex.quote(bad)}',
              status=2, stderr_has=['invalid payload name'], ncalls=0)
    reset()
    check('one-command assignments (shared getenv buffer)',
          f'PAYLOAD_ROOT={shlex.quote(str(root))} PAYLOAD_REPO={shlex.quote(str(repo))} '
          f'PAYLOAD_INSTALLER={shlex.quote(str(helper))} payload install rust',
          unset=('PAYLOAD_ROOT', 'PAYLOAD_REPO', 'PAYLOAD_INSTALLER'),
          stdout='helper: installed rust\n', argvs=[INSTALL + ['rust']])
    reset()
    check('exported and temporary variables reach the helper',
          'FAKE_MARK=temp payload install bun', stdout='helper: installed bun\n',
          extra=lambda r, g: None if (log / 'mark.0').read_text() == 'temp' else 'no env')
    reset()
    check('quoted repo/root paths stay single argv words', 'payload install python3',
          argvs=[INSTALL + ['python3']], stdout='helper: installed python3\n')

    # --- helper absence, non-executable, failure, exit propagation ------------
    reset()
    check('helper absent', 'payload install bun', status=127, ncalls=0,
          env={'PAYLOAD_INSTALLER': str(top / 'missing.sh')},
          stderr_has=['missing.sh: No such file or directory'])
    check('helper is a directory', 'payload install bun', status=126, ncalls=0,
          env={'PAYLOAD_INSTALLER': str(log)}, stderr_has=['not a regular file'])
    unreadable = top / 'unreadable.sh'
    unreadable.write_text(FAKE)
    unreadable.chmod(0o000)
    if os.geteuid() != 0:
        check('helper unreadable', 'payload install bun', status=126, ncalls=0,
              env={'PAYLOAD_INSTALLER': str(unreadable)}, stderr_has=['Permission denied'])
    check('non-executable helper runs through $BASH', 'payload install bun',
          stdout='helper: installed bun\n', ncalls=1,
          extra=lambda r, g: None if not os.access(helper, os.X_OK) else 'helper is +x')
    for code in (1, 3, 42, 255):
        reset()
        check(f'helper exit {code} propagates', 'payload install bun', status=code,
              env={'FAKE_MODE': f'fail:{code}'}, ncalls=1,
              stderr_has=[f'bl-pkg exit {code}'])
    reset()
    check('helper killed by SIGTERM -> 143', 'payload install bun', status=143,
          env={'FAKE_MODE': 'signal'}, ncalls=1, stderr_has=['bl-pkg exit 143'])
    reset()
    check('interpreter cannot be executed -> 127', 'BASH=/nonexistent/bash payload install bun',
          status=127, ncalls=0, stderr_has=['/nonexistent/bash'])
    reset()
    check('status visible to set -e and $?',
          'payload install bun; echo "rc=$?"; set -e; payload install bun; echo unreachable',
          status=7, env={'FAKE_MODE': 'fail:7'}, stdout='rc=7\n', stderr_empty=False)

    # --- remove: rollback references --------------------------------------
    reset(installed={'bun': 'txn=T-bun-1\nversion=1.2.3\n', 'gcc': 'version=14\ntxn=T-gcc-2\n'})
    check('remove multiple names in order, output ordered with helper',
          'payload remove bun gcc',
          stdout='helper: rolled back T-bun-1\npayload: removed bun\n'
                 'helper: rolled back T-gcc-2\npayload: removed gcc\n',
          argvs=[ROLLBACK + ['T-bun-1'], ROLLBACK + ['T-gcc-2']],
          extra=lambda r, g: None if not any(state.iterdir()) else 'state left behind')
    reset()
    check('install then remove round trip',
          'payload install bun rust && payload list -p --installed && payload remove rust bun'
          ' && payload list -p --installed',
          stdout='helper: installed bun\nhelper: installed rust\n'
                 'installed\tbun\t1.2.3\tbin/bun\ninstalled\trust\t-\t\n'
                 'helper: rolled back txn-rust-0\npayload: removed rust\n'
                 'helper: rolled back txn-bun-0\npayload: removed bun\n',
          argvs=[INSTALL + ['bun', 'rust'], ROLLBACK + ['txn-rust-0'],
                 ROLLBACK + ['txn-bun-0']])
    reset(installed={'bun': 'txn=T-bun-1\n'})
    check('remove not-installed + installed', 'payload remove nope bun', status=1,
          stderr_has=["'nope' is not installed"], argvs=[ROLLBACK + ['T-bun-1']],
          stdout='helper: rolled back T-bun-1\npayload: removed bun\n')
    reset()
    check('remove needs a NAME', 'payload remove', status=2, ncalls=0)
    for bad in ('../installed/bun', '-rf', '.', 'a b'):
        reset(installed={'bun': 'txn=T-bun-1\n'})
        check(f'remove rejects {bad!r}', f'payload remove {shlex.quote(bad)}', status=1,
              stderr_has=['invalid payload name'], ncalls=0)
    for label, body, why in (('no txn', 'version=1\n', 'no txn='),
                             ('empty txn', 'txn=\n', 'malformed txn='),
                             ('option txn', 'txn=--root=/\n', 'malformed txn='),
                             ('spaced txn', 'txn=a b\n', 'malformed txn='),
                             ('control txn', 'txn=a\x1bb\n', 'malformed txn='),
                             ('embedded CR txn', 'txn=T-bun-1\rhidden\n', 'malformed txn='),
                             ('NUL txn', 'txn=T-bun-1\x00hidden\n', 'malformed txn='),
                             ('overlong txn', 'txn=' + 'x' * 9000 + '\n', 'malformed txn='),
                             ('long txn field', 'txn=' + 'x' * 300 + '\n', 'malformed txn=')):
        reset(installed={'bun': body})
        check(f'malformed state: {label}', 'payload remove bun', status=1, ncalls=0,
              stderr_has=[why, "use 'pkg remove bun'"])
    reset(installed={'bun': 'txn=T-bun-1\r\n'})
    check('CRLF transaction retains complete ID', 'payload remove bun',
          argvs=[ROLLBACK + ['T-bun-1']],
          stdout='helper: rolled back T-bun-1\npayload: removed bun\n',
          env={'FAKE_MODE': 'ok-crlf'})

    reset(installed={'bun': 'txn=T-bun-1\n', 'gcc': 'txn=T-gcc-2\n', 'rust': 'txn=T-r-3\n'})
    check('rollback failure: first helper status returned, later names still tried',
          'payload remove bun gcc rust', status=9, env={'FAKE_MODE': 'failtxn:T-gcc-2'},
          argvs=[ROLLBACK + ['T-bun-1'], ROLLBACK + ['T-gcc-2'], ROLLBACK + ['T-r-3']],
          stderr_has=["rollback failed for 'gcc' (bl-pkg exit 9)"],
          stdout='helper: rolled back T-bun-1\npayload: removed bun\n'
                 'helper: rolled back T-r-3\npayload: removed rust\n')
    reset(installed={'bun': 'txn=T-bun-1\n'})
    check('remove with helper absent', 'payload remove bun', status=127, ncalls=0,
          env={'PAYLOAD_INSTALLER': str(top / 'missing.sh')})
    reset(installed={'bun': 'txn=T-bun-1\n'})
    check('remove killed helper', 'payload remove bun', status=143, ncalls=1,
          env={'FAKE_MODE': 'signal'})

    # --- shell integration: jobs, repeated calls, FDs, output failure --------
    reset()
    check('background job status survives the helper wait',
          '(exit 7) & bg=$!; payload install bun >/dev/null; wait "$bg"; echo "job=$?"',
          stdout='job=7\n', ncalls=1)
    # On one CPU the helper usually exits before the shell waits; Bash's own
    # SIGCHLD handler used to reap it first and success was reported as -1.
    reset()
    check('helper reaped by payload, not the shell, on one CPU',
          'for ((i=0;i<3;i++)); do payload install bun && payload remove bun || exit 1; '
          'done; payload list -p --installed', ncalls=6, pin=True,
          stdout=''.join('helper: installed bun\nhelper: rolled back txn-bun-%d\n'
                         'payload: removed bun\n' % (2 * i) for i in range(3)))
    reset()
    check('repeated calls in one shell leak no descriptors',
          'before=(/proc/self/fd/*); for ((i=0;i<25;i++)); do '
          'payload install bun >/dev/null; payload list -p >/dev/null; '
          'payload info bun >/dev/null; payload remove bun >/dev/null || exit 3; '
          'payload info nope 2>/dev/null; payload list >/dev/full 2>/dev/null; done; '
          'after=(/proc/self/fd/*); [[ ${#before[@]} == "${#after[@]}" ]] || exit 4; '
          'payload list -p --installed; echo ok',
          stdout='ok\n', ncalls=50)
    check('list to a full device fails', 'payload list >/dev/full', status=1,
          stderr_has=['write error'])
    check('stdout usable after a failed write', 'payload list >/dev/full 2>/dev/null; '
          'payload list -p --installed; echo "rc=$?"', stdout='rc=0\n')
    check('info to a full device fails', 'payload info bun >/dev/full', status=1,
          stderr_has=['write error'])
    big = ''.join('blpkg-v1 name=pl-%05d version=1.%d.0 provides=bin/pl-%05d\n'
                  % (i, i % 53, i) for i in range(5000))
    reset(index=big, installed={'pl-%05d' % i: 'txn=t%d\n' % i for i in range(0, 5000, 8)})
    check('5000-record INDEX counts', 'payload list | { n=0; while read -r l; do n=$((n+1)); '
          'done; echo "$n"; }; payload list -p --installed | { c=0; while read -r l; do '
          'c=$((c+1)); done; echo "$c"; }', stdout='5005\n625\n')

for label, problems, out, err in failures:
    print(f'FAIL {label}: {problems}\n  stdout={out[:400]!r}\n  stderr={err[:400]!r}')
print(f'opus-payload-installer: {checks - len(failures)}/{checks} checks passed')
raise SystemExit(1 if failures else 0)
