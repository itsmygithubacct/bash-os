#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Allocation-failure rollback for every clip mutation; empty PATH.

    CLIP_LOAD_ENV=OUT/probe.sh tests/sol-clip-faults.py BINARY

OUT comes from tests/sol-clip-build-probe.sh: the genuine buf.c and clip.c
compiled with counters that fail the Nth allocation either source makes. Each
operation is repeated with N = 1, 2, ... until it succeeds without the fault
firing. Every injected failure must return nonzero and leave the buffer bytes,
its dirty flag, every ring slot and the active entry exactly as they were; the
final success must equal an explicitly listed expected state."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
if not os.environ.get('CLIP_LOAD_ENV'):
    sys.exit('sol-clip-faults: CLIP_LOAD_ENV must name the probe loader')
child_env = {k: v for k, v in os.environ.items() if k != 'BASH_ENV'}
child_env['BASH_ENV'] = os.environ['CLIP_LOAD_ENV']
if os.environ.get('CLIP_ASAN_LIB'):
    child_env.update(LD_PRELOAD=os.environ['CLIP_ASAN_LIB'],
                     ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                     UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
q = lambda p: shlex.quote(str(p))
checks = 0
failures = []

SNAPSHOT = r'''snapshot() {
  buf lines "$b"; buf text "$b" -X; buf dirty "$b"; echo "dirty=$?"
  for k in {0..15}; do clip text "$c" -N $k -X 2>/dev/null; echo "slot$k=$?"; done
  echo active; clip text "$c" -X
}
'''
BASE = [b'zero', b'one \xc3\xa9', b'two\x00two', b'three \xf0\x9f\x98\x80', b'four', b'five']
ENTRIES = [b'E0', b'E1a\nE1b', b'E2a\nE2b\nE2c']   # pieces split on \n


def expected_snapshot(lines, dirty, ring, active):
    out = f'{len(lines)}\n{b"".join([b"\n".join(lines)]).hex()}\ndirty={0 if dirty else 1}\n'
    for k in range(16):
        if k < len(ring):
            out += b'\n'.join(ring[k]).hex() + f'\nslot{k}=0\n'
        else:
            out += f'slot{k}=1\n'
    out += 'active\n' + b'\n'.join(ring[active]).hex() + '\n'
    return out.encode()


def sweep(name, setup, op, expect):
    """Fail allocation 1, 2, ... of OP; then require EXPECT on success."""
    global checks
    fired_points = 0
    for n in range(1, 400):
        script = 'PATH=\n' + SNAPSHOT + setup + f'''
before=$(snapshot)
clipprobe reset; clipprobe alloc {n}
{op}
rc=$?
clipprobe fired; fired=$?
clipprobe reset
after=$(snapshot)
if [[ $fired == 0 ]]; then
  [[ $rc != 0 ]] || {{ echo "fault {n} swallowed" >&2; exit 92; }}
  [[ $after == "$before" ]] || {{ printf 'fault {n} changed state\\n%s\\n--\\n%s\\n' "$before" "$after" >&2; exit 93; }}
  echo fired
else
  [[ $rc == 0 ]] || {{ echo "unfaulted op failed: $rc" >&2; exit 94; }}
  printf '%s\\n' "$after"
fi
'''
        p = subprocess.run([binary, '-c', script], capture_output=True, timeout=60, env=child_env)
        checks += 1
        bad = p.returncode != 0 or b'Sanitizer' in p.stderr or b'runtime error:' in p.stderr
        if not bad and p.stdout == b'fired\n':
            fired_points += 1
            continue
        if not bad and p.stdout != expect:
            print(f'FAIL {name}: success state\n  got  {p.stdout!r}\n  want {expect!r}')
            failures.append(name)
        elif bad:
            print(f'FAIL {name} (fault {n}): exit {p.returncode}\n  {p.stderr[-2000:]!r}')
            failures.append(name)
        print(f'{name}: {fired_points} injected allocation failures rolled back, then success'
              + ('' if name not in failures else ' [FAILED]'))
        return fired_points
    failures.append(name)
    print(f'FAIL {name}: never succeeded')
    return fired_points


with tempfile.TemporaryDirectory(prefix='sol-clip-faults-') as td:
    d = Path(td)
    src = d / 'base'
    src.write_bytes(b'\n'.join(BASE))
    ring_setup = 'buf new -h s\n' + ''.join(
        f'buf insert-line "$s" {i} {e.hex()} -X\n' for i, e in enumerate(b'\n'.join(ENTRIES).split(b'\n')))
    # Entries E0 (1 piece), E1 (2 pieces), E2 (3 pieces); E2 is active.
    ring_setup += 'clip new -h c\nclip copy-line "$c" "$s" 0\nclip copy-range "$c" "$s" 1 3\nclip copy-range "$c" "$s" 3 0 5 3\n'
    ring = [[b'E0'], [b'E1a', b'E1b'], [b'E2a', b'E2b', b'E2c']]
    variants = {
        'paged': f'buf new -h b; buf load "$b" {q(src)}\n',
        'realized': f'buf new -h b; buf load "$b" {q(src)}; buf insert-line "$b" 0 x; buf delete-line "$b" 0; buf clean "$b"\n',
    }
    L = BASE
    total = 0
    for vname, vsetup in variants.items():
        setup = vsetup + ring_setup
        def case(label, op, lines, dirty, new_entry=None, active=2, select=''):
            r = [list(x) for x in ring]
            act = active
            if new_entry is not None:
                r.append(new_entry)
                act = len(r) - 1
            return sweep(f'{vname}:{label}', setup + select, op, expected_snapshot(lines, dirty, r, act))
        total += case('copy-line', 'clip copy-line "$c" "$b" 3', L, False, [L[3]])
        total += case('cut-line', 'clip cut-line "$c" "$b" 3', L[:3] + L[4:], True, [L[3]])
        total += case('copy-lines', 'clip copy-range "$c" "$b" 1 5', L, False, L[1:5])
        total += case('cut-lines', 'clip cut-range "$c" "$b" 1 5', L[:1] + L[5:], True, L[1:5])
        total += case('copy-bytes-1', 'clip copy-range "$c" "$b" 2 1 2 5', L, False, [L[2][1:5]])
        total += case('cut-bytes-1', 'clip cut-range "$c" "$b" 2 1 2 5',
                      L[:2] + [L[2][:1] + L[2][5:]] + L[3:], True, [L[2][1:5]])
        total += case('copy-bytes-n', 'clip copy-range "$c" "$b" 1 2 4 3', L, False,
                      [L[1][2:], L[2], L[3], L[4][:3]])
        total += case('cut-bytes-n', 'clip cut-range "$c" "$b" 1 2 4 3',
                      L[:1] + [L[1][:2] + L[4][3:]] + L[5:], True, [L[1][2:], L[2], L[3], L[4][:3]])
        total += case('cut-bytes-utf8-split', 'clip cut-range "$c" "$b" 1 5 3 9',
                      L[:1] + [L[1][:5] + L[3][9:]] + L[4:], True, [L[1][5:], L[2], L[3][:9]])
        for active, sel in ((2, ''), (1, 'clip yank-prev "$c"\n'), (0, 'clip yank-prev "$c"; clip yank-prev "$c"\n')):
            e = ring[active]
            total += case(f'paste-lines-{len(e)}', 'clip paste "$c" "$b" 2', L[:2] + e + L[2:], True,
                          active=active, select=sel)
            pre, tail = L[3][:4], L[3][4:]
            mid = [pre + e[0] + tail] if len(e) == 1 else [pre + e[0]] + e[1:-1] + [e[-1] + tail]
            total += case(f'paste-col-{len(e)}', 'clip paste "$c" "$b" 3 4', L[:3] + mid + L[4:], True,
                          active=active, select=sel)
            total += case(f'paste-append-{len(e)}', 'clip paste "$c" "$b" 6', L + e, True,
                          active=active, select=sel)
    # A full ring under fault keeps its oldest entry until the push succeeds.
    full = f'buf new -h b; buf load "$b" {q(src)}\nclip new -h c\n' + \
        ''.join(f'clip copy-range "$c" "$b" 0 0 0 {i % 5}; ' for i in range(16)) + 'clip yank-prev "$c"\n'
    r = [[BASE[0][:i % 5]] for i in range(16)]
    r[0] = [BASE[5]]
    total += sweep('full-ring-push', full, 'clip cut-line "$c" "$b" 5',
                   expected_snapshot(BASE[:5], True, r, 0))
    # A 15-line buffer realized by insert+delete has a 16-record array, so
    # pasting three lines must grow it: the realloc failure is swept too.
    src15 = d / 'base15'
    L15 = [f'r{i}'.encode() for i in range(15)]
    src15.write_bytes(b'\n'.join(L15))
    grow = f'buf new -h b; buf load "$b" {q(src15)}; buf insert-line "$b" 0 x; buf delete-line "$b" 0; buf clean "$b"\n' + ring_setup
    total += sweep('grow:paste-lines-3', grow, 'clip paste "$c" "$b" 5',
                   expected_snapshot(L15[:5] + ring[2] + L15[5:], True, ring, 2))
    total += sweep('grow:paste-col-3', grow, 'clip paste "$c" "$b" 5 1',
                   expected_snapshot(L15[:5] + [b'r' + b'E2a', b'E2b', b'E2c' + b'5'] + L15[6:], True, ring, 2))
    # A failed `clip new` publishes no handle.
    script = 'PATH=\nclipprobe alloc 1\nif clip new -h h; then exit 95; fi\nclipprobe reset\n[[ -z ${h+x} ]] || exit 96\nclip new -h h; [[ $h == 0 ]]; clip free "$h"'
    p = subprocess.run([binary, '-e', '-c', script], capture_output=True, timeout=60, env=child_env)
    checks += 1
    if p.returncode != 0:
        failures.append('new-alloc'); print('FAIL new-alloc', p.returncode, p.stderr[-500:])

print(f'sol-clip-faults: {checks - len(failures)}/{checks} runs passed, '
      f'{total} injected failures rolled back; failures={failures}')
sys.exit(bool(failures) or total == 0)
