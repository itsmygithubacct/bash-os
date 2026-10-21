#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""clip contract checks against an independent Python model; empty PATH.

    tests/sol-clip-check.py BINARY

The binary must provide buf and clip (or load them through CLIP_LOAD_ENV,
which becomes the child's BASH_ENV; CLIP_ASAN_LIB is preloaded with it)."""
import os
from pathlib import Path
import random
import shlex
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
checks = 0
failures = []
child_env = {k: v for k, v in os.environ.items() if k != 'BASH_ENV'}
if os.environ.get('CLIP_LOAD_ENV'):
    child_env['BASH_ENV'] = os.environ['CLIP_LOAD_ENV']
if os.environ.get('CLIP_ASAN_LIB'):
    child_env.update(LD_PRELOAD=os.environ['CLIP_ASAN_LIB'],
                     ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                     UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
q = lambda p: shlex.quote(str(p))
PRELUDE = r'''PATH=
fds() { local a=(/proc/$$/fd/*); FDS="${a[*]}"; }   # no subshell: no pipe race
reject() { local want=$1 rc=0; shift; "$@" || rc=$?
  if [[ $rc != "$want" ]]; then printf 'want %s got %s: %s\n' "$want" "$rc" "$*" >&2; exit 90; fi; }
'''


def run(name, script, stdout=None, stderr_has=(), rc=0, errexit=True):
    """Run SCRIPT in one shell. The FD table must be unchanged at exit."""
    global checks
    checks += 1
    body = ('set -e\n' if errexit else '') + PRELUDE + 'fds; fd_before=$FDS\n' + script + \
        '\nfds; [[ $FDS == "$fd_before" ]] || { echo "fd leak: $fd_before -> $FDS" >&2; exit 91; }'
    p = subprocess.run([binary, '-c', body], capture_output=True, timeout=120, env=child_env)
    problems = []
    if p.returncode != rc:
        problems.append(f'exit {p.returncode} != {rc}')
    if stdout is not None and p.stdout != stdout:
        problems.append(f'stdout {p.stdout[:400]!r} != {stdout[:400]!r}')
    for needle in stderr_has:
        if needle not in p.stderr:
            problems.append(f'stderr lacks {needle!r}')
    if b'Sanitizer' in p.stderr or b'runtime error:' in p.stderr:
        problems.append('sanitizer report')
    if problems:
        failures.append(name)
        print(f'FAIL {name}: {"; ".join(problems)}\n  stderr: {p.stderr[-1500:]!r}')
    return p


def load_buf(path):
    return f'buf new -h b; buf load "$b" {q(path)}\n'


# ---- independent model -------------------------------------------------
class Model:
    """Byte-exact model of one buf (no trailing newline) and one clip ring."""
    def __init__(self, lines):
        self.lines = list(lines)
        self.dirty = False
        self.slots = [None] * 16
        self.head = self.active = self.fill = 0

    def push(self, entry):
        nxt = self.fill if self.fill < 16 else (self.head + 1) % 16
        if self.fill < 16:
            self.fill += 1
        self.slots[nxt] = list(entry)
        self.head = self.active = nxt

    def change(self, new):
        if new != self.lines:
            self.dirty = True
        self.lines = new

    def line_range(self, s, e, cut):
        if e < s:
            return 2
        n = len(self.lines)
        if s >= n:
            return 1
        e = min(e, n)
        self.push(self.lines[s:e])
        if cut:
            self.change(self.lines[:s] + self.lines[e:])
        return 0

    def byte_range(self, fl, fc, tl, tc, cut):
        L = self.lines
        if tl < fl or (tl == fl and tc < fc):
            return 2
        if fl >= len(L) or tl >= len(L) or fc > len(L[fl]) or tc > len(L[tl]):
            return 2
        if fl == tl:
            entry = [L[fl][fc:tc]]
            new = L[:fl] + [L[fl][:fc] + L[fl][tc:]] + L[fl + 1:]
        else:
            entry = [L[fl][fc:]] + L[fl + 1:tl] + [L[tl][:tc]]
            new = L[:fl] + [L[fl][:fc] + L[tl][tc:]] + L[tl + 1:]
        self.push(entry)
        if cut:
            self.change(new)
        return 0

    def paste(self, i, col=None):
        L = self.lines
        if self.fill == 0:
            return 1
        if i > len(L) or (col is not None and i >= len(L)):
            return 2
        e = self.slots[self.active]
        if col is None:
            self.change(L[:i] + e + L[i:])
            return 0
        if col > len(L[i]):
            return 2
        if not e:
            return 0
        pre, tail = L[i][:col], L[i][col:]
        if len(e) == 1:
            mid = [pre + e[0] + tail]
        else:
            mid = [pre + e[0]] + e[1:-1] + [e[-1] + tail]
        self.change(L[:i] + mid + L[i + 1:])
        return 0

    def rotate(self, d):
        if self.fill == 0:
            return 1
        self.active = (self.active + d) % self.fill
        return 0

    def clear(self):
        if self.fill:
            self.slots[self.active] = []
        return 0

    def text(self, slot=None):
        if self.fill == 0:
            return b''
        e = self.slots[self.active if slot is None else slot]
        return b''.join(p + b'\n' for p in e)

    def state(self):
        joined = b'\n'.join(self.lines).hex()
        return (f'{len(self.lines)}\n{joined}\n{0 if self.dirty else 1}\n'
                .encode() + self.text() + b'|\n')


STATE = 'buf lines "$b"; buf text "$b" -X; buf dirty "$b"; echo $?; clip text "$c"; echo "|"\n'

with tempfile.TemporaryDirectory(prefix='sol-clip-check-') as td:
    d = Path(td)

    # ---- line and byte ranges, exact bytes -----------------------------
    src = d / 'lines'
    base = [b'alpha', b'', b'caf\xc3\xa9 \xf0\x9f\x98\x80', b'nul\x00byte', b'cr\r', b'\xff\xfe', b'omega']
    src.write_bytes(b'\n'.join(base))
    base_hex, base5_hex = b'\n'.join(base).hex(), b'\n'.join(base[:5]).hex()
    m = Model(base)

    def scenario(name, ops):
        """ops: list of (shell, model-callable) evaluated in one shell."""
        script = load_buf(src) + 'clip new -h c\n'
        expected = b''
        model = Model(base)
        for sh, fn in ops:
            script += f'{sh}; echo "rc=$?"\n' + STATE
            expected += f'rc={fn(model)}\n'.encode() + model.state()
        script += 'clip free "$c"; buf free "$b"'
        run(name, script, stdout=expected, errexit=False)

    C = '"$c" "$b"'
    scenario('line-verbs', [
        (f'clip copy-line {C} 2', lambda m: m.line_range(2, 3, False)),
        (f'clip paste {C} 0', lambda m: m.paste(0)),
        (f'clip cut-line {C} 4', lambda m: m.line_range(4, 5, True)),
        (f'clip paste {C} 8', lambda m: m.paste(8)),
        (f'clip cut-range {C} 1 4', lambda m: m.line_range(1, 4, True)),
        (f'clip paste {C} 2', lambda m: m.paste(2)),
        (f'clip copy-range {C} 3 99', lambda m: m.line_range(3, 99, False)),
        (f'clip paste {C} 1', lambda m: m.paste(1)),
        (f'clip copy-line {C} 99', lambda m: m.line_range(99, 100, False)),
        (f'clip cut-range {C} 5 2', lambda m: m.line_range(5, 2, True)),
    ])
    scenario('byte-ranges', [
        (f'clip copy-range {C} 0 1 0 4', lambda m: m.byte_range(0, 1, 0, 4, False)),
        (f'clip paste {C} 6 2', lambda m: m.paste(6, 2)),
        (f'clip cut-range {C} 0 3 2 4', lambda m: m.byte_range(0, 3, 2, 4, True)),
        (f'clip paste {C} 3 9', lambda m: m.paste(3, 9)),
        (f'clip paste {C} 0', lambda m: m.paste(0)),
        (f'clip cut-range {C} 1 0 2 0', lambda m: m.byte_range(1, 0, 2, 0, True)),
        (f'clip paste {C} 1 0', lambda m: m.paste(1, 0)),
        (f'clip copy-range {C} 2 0 4 0', lambda m: m.byte_range(2, 0, 4, 0, False)),
        (f'clip paste {C} 5 3', lambda m: m.paste(5, 3)),
        (f'clip cut-range {C} 0 0 9 0', lambda m: m.byte_range(0, 0, 9, 0, True)),
        (f'clip cut-range {C} 0 99 0 99', lambda m: m.byte_range(0, 99, 0, 99, True)),
        (f'clip cut-range {C} 1 3 1 1', lambda m: m.byte_range(1, 3, 1, 1, True)),
        (f'clip paste {C} 0 99', lambda m: m.paste(0, 99)),
    ])

    # ---- Unicode byte boundaries ----------------------------------------
    # Splitting a multibyte sequence is permitted and byte-exact; cutting and
    # pasting back at the same place restores the original exactly.
    scenario('utf8-boundaries', [
        # 4-byte U+1F600 occupies bytes 6..9 of line 2; cut its middle two.
        (f'clip cut-range {C} 2 7 2 9', lambda m: m.byte_range(2, 7, 2, 9, True)),
        (f'clip paste {C} 2 7', lambda m: m.paste(2, 7)),
        # 2-byte U+00E9 at 3..4: cut the trailing byte alone, then restore.
        (f'clip cut-range {C} 2 4 2 5', lambda m: m.byte_range(2, 4, 2, 5, True)),
        (f'clip paste {C} 2 4', lambda m: m.paste(2, 4)),
        # Whole-codepoint boundaries across lines.
        (f'clip cut-range {C} 2 3 3 3', lambda m: m.byte_range(2, 3, 3, 3, True)),
        (f'clip paste {C} 2 3', lambda m: m.paste(2, 3)),
    ])
    run('utf8-restore-exact', load_buf(src) + 'clip new -h c\n' + f'''
before=$(buf text "$b" -X)
clip cut-range {C} 2 8 2 9; [[ $(clip text "$c" -X) == 98 ]] || exit 3
[[ $(buf line "$b" 2 -X) == 636166c3a920f09f80 ]] || exit 4
clip paste {C} 2 8; [[ $(buf text "$b" -X) == "$before" ]] || exit 5
clip copy-range {C} 2 3 2 5; [[ $(clip text "$c" -X) == c3a9 ]] || exit 6
clip copy-range {C} 2 6 2 10; [[ $(clip text "$c" -X) == f09f9880 ]] || exit 7
clip free "$c"; buf free "$b"''')
    # Combining sequence (e + U+0301) and a ZWJ emoji family split mid-cluster.
    comb = d / 'combining'
    comb_lines = [b'e\xcc\x81x', b'\xf0\x9f\x91\xa9\xe2\x80\x8d\xf0\x9f\x91\xa7']
    comb.write_bytes(b'\n'.join(comb_lines))
    run('utf8-clusters', load_buf(comb) + 'clip new -h c\n' + f'''
before=$(buf text "$b" -X)
clip cut-range {C} 0 1 0 3; [[ $(clip text "$c" -X) == cc81 ]] || exit 3
[[ $(buf line "$b" 0 -X) == 6578 ]] || exit 4
clip cut-range {C} 1 4 1 7; [[ $(clip text "$c" -X) == e2808d ]] || exit 5
clip paste {C} 1 4; clip yank-prev "$c"; clip paste {C} 0 1
[[ $(buf text "$b" -X) == "$before" ]] || exit 6
clip free "$c"; buf free "$b"''')

    # ---- yank ring rotation and wraparound ------------------------------
    ring_src = d / 'ring'
    ring_lines = [f'L{i}'.encode() for i in range(40)]
    ring_src.write_bytes(b'\n'.join(ring_lines))
    def ring_ops():
        ops = []
        for i in range(10):
            ops.append((f'clip copy-line {C} {i}', lambda m, i=i: m.line_range(i, i + 1, False)))
        ops += [(f'clip yank-prev "$c"', lambda m: m.rotate(-1))] * 3
        ops += [(f'clip yank-next "$c"', lambda m: m.rotate(1))] * 12   # wraps past newest
        ops += [(f'clip yank-prev "$c"', lambda m: m.rotate(-1))] * 11  # wraps past oldest
        for i in range(10, 22):  # fill to 16, then overwrite the oldest four
            ops.append((f'clip copy-line {C} {i}', lambda m, i=i: m.line_range(i, i + 1, False)))
        ops += [(f'clip yank-prev "$c"', lambda m: m.rotate(-1))] * 5
        for i in range(22, 25):  # after rotation: still replaces the oldest
            ops.append((f'clip copy-line {C} {i}', lambda m, i=i: m.line_range(i, i + 1, False)))
        ops += [(f'clip yank-next "$c"', lambda m: m.rotate(1))] * 17
        ops += [(f'clip yank-prev "$c"', lambda m: m.rotate(-1))] * 33
        ops += [(f'clip clear "$c"', lambda m: m.clear()),
                (f'clip paste {C} 0', lambda m: m.paste(0)),
                (f'clip yank-prev "$c"', lambda m: m.rotate(-1)),
                (f'clip paste {C} 0', lambda m: m.paste(0))]
        return ops
    ops = ring_ops()
    script = load_buf(ring_src) + 'clip new -h c\n'
    expected = b''
    rm = Model(ring_lines)
    for sh, fn in ops:
        script += f'{sh}; echo "rc=$?"; clip text "$c"\n'
        expected += f'rc={fn(rm)}\n'.encode() + rm.text()
    for k in range(16):  # every physical slot, after wraparound
        script += f'clip text "$c" -N {k}; echo "rc=$?"\n'
        expected += rm.text(k) + b'rc=0\n'
    script += 'clip free "$c"; buf free "$b"'
    run('ring-wraparound', script, stdout=expected, errexit=False)
    run('ring-replaces-oldest-after-rotation', load_buf(ring_src) + f'''clip new -h c
for i in {{0..15}}; do clip copy-line {C} $i; done
clip yank-prev "$c"; clip yank-prev "$c"; clip yank-prev "$c"
clip copy-line {C} 16
for k in {{0..15}}; do printf '%s ' "$(clip text "$c" -N $k)"; done; echo
clip text "$c"; clip yank-prev "$c"; clip text "$c"; clip yank-next "$c"; clip yank-next "$c"; clip text "$c"
clip free "$c"; buf free "$b"''',
        stdout=b'L16 L1 L2 L3 L4 L5 L6 L7 L8 L9 L10 L11 L12 L13 L14 L15 \nL16\nL15\nL1\n')
    run('ring-empty', '''clip new -h c; buf new -h b
reject 1 clip yank-prev "$c"; reject 1 clip yank-next "$c"
reject 1 clip paste "$c" "$b" 0; clip text "$c"; clip clear "$c"
reject 1 clip text "$c" -N 0; reject 2 clip text "$c" -N 16
reject 1 clip copy-range "$c" "$b" 0 0
buf insert-line "$b" 0 x; clip copy-line "$c" "$b" 0
clip text "$c" -N 0; reject 1 clip text "$c" -N 1
clip free "$c"; buf free "$b"''', stdout=b'x\n',
        stderr_has=[b'yank-prev: yank ring is empty', b'paste: yank ring is empty',
                    b'text: slot 0 is not in use'])

    # ---- empty regions ---------------------------------------------------
    run('empty-regions', load_buf(src) + f'''clip new -h c
clip copy-range {C} 2 2; clip text "$c"; echo "[$(clip text "$c" -X)]"
before=$(buf text "$b" -X)
clip paste {C} 0; clip paste {C} 2 2; reject 1 buf dirty "$b"
clip cut-range {C} 3 3; reject 1 buf dirty "$b"
clip cut-range {C} 2 1 2 1; clip text "$c"; echo "[$(clip text "$c" -X)]"
reject 1 buf dirty "$b"; clip paste {C} 0 3; reject 1 buf dirty "$b"
[[ $(buf text "$b" -X) == "$before" ]]
clip paste {C} 7; [[ $(buf lines "$b") == 8 && -z $(buf line "$b" 7) ]]; buf dirty "$b"
buf delete-line "$b" 7; buf clean "$b"
clip copy-line {C} 1; clip text "$c"; echo "[$(clip text "$c" -X)]"
clip clear "$c"; clip paste {C} 4; clip paste {C} 4 1; reject 1 buf dirty "$b"
[[ $(buf text "$b" -X) == "$before" ]]
clip free "$c"; buf free "$b"
buf new -h e; clip new -h c; reject 1 clip copy-line "$c" "$e" 0
reject 2 clip copy-range "$c" "$e" 0 0 0 0; reject 1 clip paste "$c" "$e" 0 0
buf insert-line "$e" 0 q; clip cut-line "$c" "$e" 0; [[ $(buf lines "$e") == 0 ]]
reject 2 clip paste "$c" "$e" 0 0; reject 2 clip paste "$c" "$e" 1
clip paste "$c" "$e" 0; [[ $(buf text "$e") == q ]]
clip free "$c"; buf free "$e"''', stdout=b'[]\n\n[]\n\n[]\n')

    # ---- stale handles and slot reuse -----------------------------------
    run('stale-clip-handle', f'''clip new -h c; buf new -h b; buf insert-line "$b" 0 x
clip free "$c"
for v in "copy-line $c $b 0" "cut-line $c $b 0" "copy-range $c $b 0 1" "cut-range $c $b 0 0 0 1" \\
         "paste $c $b 0" "yank-prev $c" "yank-next $c" "text $c" "clear $c" "free $c"; do
  reject 2 clip $v
done
for h in "" " " -1 32 1x 99999999999999999999 0x0; do reject 2 clip text "$h"; done
[[ $(buf text "$b") == x ]]; buf free "$b"''', stderr_has=[b"bad clip handle ''", b"bad clip handle '32'"])
    run('stale-buf-handle', load_buf(src) + f'''clip new -h c
clip copy-range {C} 0 3 2 4; want=$(clip text "$c" -X)
old=$b; buf free "$b"
reject 2 clip copy-line "$c" "$old" 0; reject 2 clip paste "$c" "$old" 0
reject 2 clip cut-range "$c" "$old" 0 0 0 1; reject 2 clip paste "$c" 99 0
[[ $(clip text "$c" -X) == "$want" ]]
buf new -h n; [[ $n == "$old" ]]          # slot reused: no generation number
clip paste "$c" "$n" 0; [[ $(buf text "$n" -X) == "$want" ]]
# The entry is a copy: reloading (unmapping) its source leaves it intact.
buf load "$n" {q(src)}; clip copy-range "$c" "$n" 2 0 3 5; want=$(clip text "$c" -X)
buf load "$n" {q(ring_src)}; [[ $(clip text "$c" -X) == "$want" ]]
buf free "$n"; [[ $(clip text "$c" -X) == "$want" ]]
clip free "$c"''', stderr_has=[b'buf slot 0 invalid'])
    run('handle-table', '''hs=()
for i in {0..31}; do clip new -h h; hs+=("$h"); done
reject 1 clip new -h h; reject 1 clip new
clip free "${hs[7]}"; clip new -h h; [[ $h == "${hs[7]}" ]]
for h in "${hs[@]}"; do clip free "$h"; done
clip new -h h; [[ $h == 0 ]]; clip free 0''', stderr_has=[b'handle table full'])

    # ---- invalid input ---------------------------------------------------
    run('invalid-input', load_buf(src) + f'''clip new -h c
reject 2 clip; reject 2 clip bogus; reject 2 clip new -x
reject 2 clip copy-line "$c" "$b"; reject 2 clip copy-line "$c" "$b" 0 1
reject 2 clip copy-range "$c" "$b" 0; reject 2 clip copy-range "$c" "$b" 0 1 2
reject 2 clip copy-range "$c" "$b" 0 1 2 3 4; reject 2 clip paste "$c" "$b"
reject 2 clip paste "$c" "$b" 0 0 0; reject 2 clip yank-prev "$c" x
reject 2 clip clear; reject 2 clip free "$c" "$c"
for n in -1 "" x 1.5 99999999999999999999 " "; do
  reject 2 clip copy-line "$c" "$b" "$n"; reject 2 clip copy-line "$c" "$n" 0
  reject 2 clip paste "$c" "$b" "$n"; reject 2 clip paste "$c" "$b" 0 "$n"
done
reject 2 clip copy-range "$c" "$b" 3 0 2 0; reject 2 clip copy-range "$c" "$b" 1 1 1 0
reject 2 clip copy-range "$c" "$b" 0 6 0 7; reject 2 clip copy-range "$c" "$b" 0 0 7 0
reject 2 clip copy-range "$c" "$b" 0 0 1 1
reject 2 clip text "$c" -N 16; reject 2 clip text "$c" -N -1; reject 2 clip text "$c" -F x
reject 2 clip text "$c" -Q; reject 2 clip text "$c" -X -F 2
clip copy-line {C} 0
reject 2 clip paste {C} 8; reject 2 clip paste {C} 7 0; reject 2 clip paste {C} 0 6
# Nothing above may have changed the buffer or the ring.
[[ $(clip text "$c") == alpha ]]; clip yank-prev "$c"; [[ $(clip text "$c") == alpha ]]
reject 1 clip text "$c" -N 1; reject 1 buf dirty "$b"
[[ $(buf text "$b" -X) == {base_hex} ]]
clip free "$c"; buf free "$b"''', stderr_has=[b"invalid integer ''", b'unknown verb: bogus',
                                             b'invalid range', b'range column out of bounds'])

    # ---- output and binding failures -------------------------------------
    run('output-failures', load_buf(src) + f'''clip new -h c; clip copy-range {C} 0 5
reject 1 clip text "$c" >/dev/full; reject 1 clip text "$c" -X >/dev/full
reject 1 clip text "$c" -F 9; exec 9>/dev/full; reject 1 clip text "$c" -F 9; exec 9>&-
[[ $(clip text "$c" -X) == {base5_hex} ]]
clip text "$c" -F 1 >/dev/null
reject 1 clip new >/dev/full
readonly RO=1; reject 1 clip new -h RO
clip new -h n; [[ $n == 1 ]]; clip free "$n"
clip free "$c"; buf free "$b"''', stderr_has=[b'text: write: No space left on device',
                                             b'RO: variable is not assignable'])

    # Invalid destinations are rejected before a handle is allocated, so the
    # next valid publication still receives the first free slot. Readonly
    # scalars and namerefs keep failing after allocation and release it.
    run('invalid-hvar-destination', '''
reject 2 clip new -h ''
reject 2 clip new -h bad-name
reject 2 clip new -h 1bad
reject 2 clip new -h 'a[0]'
reject 2 clip new -h 'has space'
clip new -h h; [[ $h == 0 ]]; clip free "$h"
readonly RO=1
reject 1 clip new -h RO
declare -n ref=RO
reject 1 clip new -h ref
declare -n ok=target
clip new -h ok; [[ $target == 0 && $ok == 0 ]]
clip free "$target"
unset -n ok
clip new -h h; [[ $h == 0 ]]; clip free "$h"
''', stderr_has=[b'not a valid identifier', b'RO: variable is not assignable',
                 b'ref: variable is not assignable'])

    # ---- large entries, embedded newlines/NULs, -F ----------------------
    big = d / 'big'
    rnd = random.Random(1907)
    big_lines = [bytes(rnd.randrange(256) for _ in range(rnd.randrange(90))).replace(b'\n', b'.')
                 for _ in range(9000)]
    big_lines[4000] = b'Z' * (1 << 20)          # one 1 MiB line
    big_lines[3999], big_lines[4001] = b'head-of-3999', b'tail-of-4001'
    big_lines[2047], big_lines[2049] = b'span-start', b'span-end'
    big.write_bytes(b'\n'.join(big_lines))
    out = d / 'out'
    script = load_buf(big) + f'''clip new -h c
clip copy-range {C} 10 8010; clip text "$c" -F 3 3>{q(out)}
clip copy-range {C} 1023 3073; clip text "$c" -F 3 3>{q(out)}.ckpt
clip copy-range {C} 2047 1 2049 2; clip text "$c" -F 3 3>{q(out)}.span
clip copy-line {C} 8999; clip text "$c" -F 3 3>{q(out)}.last
clip cut-range {C} 3999 5 4001 7; clip paste {C} 3999 5
buf text "$b" -F 4 4>{q(out)}.buf
buf insert-line "$b" 0 0a000a -X; clip cut-line {C} 0; clip text "$c" -F 5 5>{q(out)}.nl
clip free "$c"; buf free "$b"'''
    run('large-and-embedded', script)
    if out.exists():
        expect = b''.join(x + b'\n' for x in big_lines[10:8010])
        ok = (out.read_bytes() == expect and (Path(str(out) + '.buf').read_bytes() == b'\n'.join(big_lines))
              and Path(str(out) + '.nl').read_bytes() == b'\n\x00\n\n'
              # paged copies that start past a 1,024-line checkpoint
              and Path(str(out) + '.ckpt').read_bytes() == b''.join(x + b'\n' for x in big_lines[1023:3073])
              and Path(str(out) + '.span').read_bytes() == b''.join(x + b'\n' for x in
                  [big_lines[2047][1:], big_lines[2048], big_lines[2049][:2]])
              and Path(str(out) + '.last').read_bytes() == big_lines[8999] + b'\n')
        if not ok:
            failures.append('large-and-embedded-bytes')
            print('FAIL large-and-embedded-bytes')
        checks += 1

    # ---- seeded model sequence in one shell -------------------------------
    seq = d / 'seq'
    rnd = random.Random(20261020)
    alphabet = [b'a', b'b', b'\x00', b'\xc3\xa9', b'\xf0\x9f\x98\x80', b'\r', b'\xff', b' ']
    seq_lines = [b''.join(rnd.choice(alphabet) for _ in range(rnd.randrange(8))) for _ in range(30)]
    seq.write_bytes(b'\n'.join(seq_lines))
    sm = Model(seq_lines)
    script = load_buf(seq) + 'clip new -h c\n'
    expected = b''
    op_log = []
    for step in range(500):
        n = len(sm.lines)
        r = rnd.random()
        i = rnd.randrange(n + 2)
        j = rnd.randrange(n + 2)
        if r < .12:
            cut = rnd.random() < .5
            sh = f'clip {"cut" if cut else "copy"}-line {C} {i}'
            fn = lambda m, i=i, cut=cut: m.line_range(i, i + 1, cut)
        elif r < .27:
            cut = rnd.random() < .5
            s, e = sorted((i, j)) if rnd.random() < .9 else (j, i)
            sh = f'clip {"cut" if cut else "copy"}-range {C} {s} {e}'
            fn = lambda m, s=s, e=e, cut=cut: m.line_range(s, e, cut)
        elif r < .50:
            cut = rnd.random() < .5
            fl, tl = sorted((min(i, n), min(j, n)))
            if rnd.random() < .5:
                tl = min(fl + rnd.randrange(2), n)
            fl_len = len(sm.lines[fl]) if fl < n else 0
            tl_len = len(sm.lines[tl]) if tl < n else 0
            fc = rnd.randrange(fl_len + 2)
            tc = rnd.randrange(tl_len + 2)
            if fl == tl and tc < fc and rnd.random() < .9:
                fc, tc = tc, fc
            sh = f'clip {"cut" if cut else "copy"}-range {C} {fl} {fc} {tl} {tc}'
            fn = lambda m, a=(fl, fc, tl, tc), cut=cut: m.byte_range(*a, cut)
        elif r < .62:
            sh = f'clip paste {C} {i}'
            fn = lambda m, i=i: m.paste(i)
        elif r < .80:
            col = rnd.randrange((len(sm.lines[i]) if i < n else 0) + 2)
            sh = f'clip paste {C} {i} {col}'
            fn = lambda m, i=i, col=col: m.paste(i, col)
        elif r < .88:
            sh = 'clip yank-prev "$c"'
            fn = lambda m: m.rotate(-1)
        elif r < .94:
            sh = 'clip yank-next "$c"'
            fn = lambda m: m.rotate(1)
        elif r < .97:
            sh = 'clip clear "$c"'
            fn = lambda m: m.clear()
        else:
            sh = 'buf clean "$b"'
            fn = lambda m: setattr(m, 'dirty', False) or 0
        script += f'{sh} 2>/dev/null; echo "rc=$?"\n' + STATE
        op_log.append(sh)
        expected += f'rc={fn(sm)}\n'.encode() + sm.state()
        if n > 400:   # keep the buffer bounded
            script += f'clip cut-range {C} 0 200 >/dev/null; buf clean "$b"\n'
            sm.line_range(0, 200, True)
            sm.dirty = False
    for k in range(16):
        script += f'clip text "$c" -N {k} -X 2>/dev/null; echo "rc=$?"\n'
        expected += ((b'\n'.join(sm.slots[k]).hex().encode() + b'\nrc=0\n') if k < sm.fill else b'rc=1\n')
    script += 'clip free "$c"; buf free "$b"'
    p = run('model-sequence-500', script, stdout=expected, errexit=False)
    if p.stdout != expected:
        a, b = p.stdout.split(b'\n'), expected.split(b'\n')
        k = next((x for x in range(min(len(a), len(b))) if a[x] != b[x]), None)
        print('  first divergence at output line', k, a[k - 3:k + 2] if k else '', b[k - 3:k + 2] if k else '')
        if k is not None:
            step = b[:k].count(b'|')
            print('  during step', step, op_log[step - 1:step + 1])

print(f'sol-clip-check: {checks - len(failures)}/{checks} passed; failures={failures}')
sys.exit(bool(failures))
