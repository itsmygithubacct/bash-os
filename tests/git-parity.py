#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a git scenario under bash-os and under real git, and compare everything.

Usage: python3 tests/git-parity.py [BINARY] [SCENARIO...]

A scenario is a shell script of git commands in tests/git/. It runs twice in
fresh directories:

  bash-os   BINARY executes the script with an empty PATH, so bash-os's own
            `git` builtin answers every git call.
  git       /bin/bash executes it with real git on PATH.

Both sides get the same pinned environment: LC_ALL=C, TZ=UTC, an empty HOME,
GIT_CONFIG_NOSYSTEM=1, and fixed author and committer identities and dates, so
object ids are reproducible and comparable.

The comparison is exit status, stdout, and stderr (ignoring `hint:` advice),
then the repository itself, read by real git in both trees: every ref, HEAD and
its tree, the index, `status --porcelain=v2`, the working tree's files with
their modes and contents, and `fsck --strict`.

A scenario names what it needs in `# requires:` (commands) and
`# requires-feature:` (a whole feature, such as patch output) lines, and is
skipped while bash-os lacks any of them, so a scenario for work still to come
can sit in the tree. The harness also checks itself on every run: each
scenario must compare equal to itself run twice under real git, a deliberately
altered tree must be detected, and a scenario that fails under git is
reported rather than passing because both sides failed alike.
"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash')
if not binary.is_absolute():
    binary = (ROOT/binary).resolve()
names = sys.argv[2:]
GIT = shutil.which('git')
checks = 0
problems = []

ENV = {
    'LC_ALL': 'C',
    'TZ': 'UTC',
    'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_TERMINAL_PROMPT': '0',
    # Anything that would open an editor takes the message it was given.
    'GIT_EDITOR': 'true',
    'GIT_AUTHOR_NAME': 'Parity Author',
    'GIT_AUTHOR_EMAIL': 'author@bash-os.test',
    'GIT_AUTHOR_DATE': '1750000000 +0000',
    'GIT_COMMITTER_NAME': 'Parity Committer',
    'GIT_COMMITTER_EMAIL': 'committer@bash-os.test',
    'GIT_COMMITTER_DATE': '1750000100 +0000',
}


def scenarios():
    found = sorted((ROOT/'tests/git').glob('*.sh'))
    if not names:
        return found
    chosen = [path for path in found if path.stem in names or path.name in names]
    missing = set(names) - {path.stem for path in chosen} - {path.name for path in chosen}
    if missing:
        raise SystemExit(f'git-parity: no such scenario: {", ".join(sorted(missing))}')
    return chosen


def implemented():
    """What bash-os's git has: its commands, and the features it declares.

    A scenario can need a whole feature — patch output, say — that having
    the command does not imply, so `git --list-features` names those.
    """
    result = subprocess.run([binary, '--noprofile', '--norc', '-c',
                             'PATH=; [[ $(type -t git) == builtin ]] || exit 1; '
                             'git --list-cmds; git --list-features'],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return set()
    return set(result.stdout.split())


def required(script):
    """A scenario's "# requires: ..." lines name the commands it uses."""
    commands = set()
    for line in script.read_text().splitlines()[:20]:
        stripped = line.strip()
        if not stripped.startswith('#'):
            continue
        for marker in ('requires:', 'requires-feature:'):
            if marker in stripped:
                commands |= set(stripped.split(marker, 1)[1].split())
                break
    return commands


def run_scenario(script, workdir, home, side):
    """Execute one scenario. bash-os runs it with an empty PATH."""
    workdir.mkdir(parents=True)
    home.mkdir(parents=True)
    env = {**ENV, 'HOME': str(home)}
    if side == 'bash-os':
        argv = [str(binary), '--noprofile', '--norc', str(script)]
        env['PATH'] = ''
    else:
        argv = ['/bin/bash', '--noprofile', '--norc', str(script)]
        env['PATH'] = '/usr/bin:/bin'
    result = subprocess.run(argv, cwd=workdir, env=env, capture_output=True, timeout=300)
    stderr = b'\n'.join(line for line in result.stderr.splitlines()
                        if not line.startswith(b'hint:'))
    return {'status': result.returncode, 'stdout': result.stdout, 'stderr': stderr}


def git_out(directory, *args):
    """Ask real git about a repository, whoever wrote it."""
    result = subprocess.run([GIT, '-C', str(directory), *args],
                            capture_output=True, env={**ENV, 'HOME': str(directory)})
    return result.returncode, result.stdout


def worktree(directory):
    """Every file in the working tree with its mode and content digest."""
    listing = []
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory)
        if relative.parts and relative.parts[0] == '.git':
            continue
        if path.is_symlink():
            listing.append(f'symlink {relative} -> {os.readlink(path)}')
        elif path.is_dir():
            listing.append(f'dir     {relative}')
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            listing.append(f'file    {relative} {path.stat().st_mode & 0o777:o} {digest}')
    return '\n'.join(listing)


def state(directory):
    """What the repository holds, read by real git so both sides agree."""
    facts = {'worktree': worktree(directory)}
    if not (directory/'.git').exists():
        return facts
    for label, args in (
            ('refs', ('for-each-ref', '--format=%(refname) %(objecttype) %(objectname)')),
            ('head', ('rev-parse', '--symbolic-full-name', 'HEAD')),
            ('index', ('ls-files', '-s')),
            ('status', ('status', '--porcelain=v2', '--branch')),
            ('stash', ('stash', 'list')),
            ('log', ('log', '--all', '--format=%H %T %P %an %ae %ad %cn %ce %cd %s', '--date=raw')),
            ('reflog', ('log', '-g', '--all', '--format=%H %gd %gn %ge %gs', '--date=raw')),
            ('fsck', ('fsck', '--strict', '--no-progress')),
            # `dangling` lines are not reported here: an object left
            # unreferenced is each implementation's own business, while
            # anything else fsck says is not.
    ):
        status, output = git_out(directory, *args)
        if label == 'fsck':
            output = b'\n'.join(line for line in output.splitlines()
                                 if not line.startswith(b'dangling '))
        facts[label] = (status, output)
    return facts


def compare(label, left, right):
    global checks
    differences = []
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            differences.append(f'  {key}:\n    bash-os: {left.get(key)!r}\n    git:     {right.get(key)!r}')
    checks += 1
    if differences:
        problems.append(label + ' differs:\n' + '\n'.join(differences))
        return False
    return True


def parity(script, left_side, right_side, corrupt=False):
    """Run one scenario on both sides and compare the run and the repository."""
    with tempfile.TemporaryDirectory(prefix='git-parity-') as directory:
        base = Path(directory)
        left_dir, right_dir = base/'left/repo', base/'right/repo'
        left = run_scenario(script, left_dir, base/'left/home', left_side)
        right = run_scenario(script, right_dir, base/'right/home', right_side)
        if corrupt:
            (left_dir/'corrupted-by-the-self-check').write_text('difference\n')
        if right_side == 'git' and right['status'] != 0 and not corrupt:
            problems.append(f'{script.stem}: the scenario itself fails under real git '
                            f'(status {right["status"]}): {right["stderr"].decode(errors="replace")[:2000]}')
        ok = compare(f'{script.stem}: run', left, right)
        ok &= compare(f'{script.stem}: repository', state(left_dir), state(right_dir))
        return ok


if not GIT:
    raise SystemExit('git-parity: real git is required as the reference')
version = subprocess.run([GIT, '--version'], capture_output=True, text=True).stdout.strip()
found = scenarios()
if not found:
    raise SystemExit('git-parity: no scenarios in tests/git/')

have = implemented()
ran = 0
for script in found:
    missing = required(script) - have
    if not have:
        print(f'skip {script.stem}: {binary.name} has no git builtin', flush=True)
    elif missing:
        print(f'skip {script.stem}: git has no {" ".join(sorted(missing))}', flush=True)
    else:
        parity(script, 'bash-os', 'git')
        ran += 1

# The harness checks itself: the same scenario run twice under real git must
# compare equal, and an altered tree must be caught.
for script in found:
    if not parity(script, 'git', 'git'):
        problems.append(f'{script.stem}: self-check found a difference between two git runs')
    before = len(problems)
    parity(script, 'git', 'git', corrupt=True)
    if len(problems) == before:
        problems.append(f'{script.stem}: self-check did not notice an altered working tree')
    else:
        problems.pop()  # the detected difference was the point

for problem in problems:
    print(problem, file=sys.stderr)
print(f'git-parity: {checks} comparisons against {version}, '
      f'{ran} of {len(found)} scenario(s) run against bash-os, '
      f'{len(problems)} problem(s)')
raise SystemExit(1 if problems else 0)
