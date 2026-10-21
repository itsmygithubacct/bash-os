#!/usr/bin/env python3
"""vi line deletion: cursor clamping, counts, undo/redo and ex :d.

Every case runs the production builtin through `vi --keys` (and the
ex path through `vi -c`) under an empty PATH, checks the written bytes
against a fixed expected value, and, when nvim is installed, checks
that an interactive nvim on a private PTY produces the same bytes for
the same keystrokes or ex command lines. nvim runs
with `nofixeol` (vi keeps a file's missing final newline) and
`startofline` (vi puts the cursor on the first non-blank after G and
linewise deletes, as POSIX vi does).

usage: tests/opus-vi-dd.py [BASH]    (default out/bash)
Set OPUS_VI_REQUIRE_NVIM=1 to fail instead of skipping reference checks.
"""
import fcntl
import hashlib
import os
import pty
import select
import struct
import termios
import threading
import time
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'out/bash').resolve())
nvim = shutil.which('nvim')
if not nvim and os.environ.get('OPUS_VI_REQUIRE_NVIM') == '1':
    sys.exit('nvim reference required but not installed')
checks = 0
ref_checks = 0
skipped = 0
ESC = b'\x1b'
CR = b'\r'
CTRL_R = b'\x12'


def child_env():
    env = {**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}
    if os.environ.get('HELPER_LOAD_ENV'):
        env.update(BASH_ENV=os.environ['HELPER_LOAD_ENV'],
                   LD_PRELOAD=os.environ['HELPER_ASAN_LIB'],
                   ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env


def shell(script, *args, rc=0, cwd=None):
    """Run `script` in the built bash with PATH empty, so vi must be the builtin."""
    global checks
    p = subprocess.run([binary, '-c', 'PATH=\n' + script, '_', *map(str, args)],
                       capture_output=True, timeout=60, env=child_env(), cwd=cwd,
                       start_new_session=True)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    assert p.returncode == rc, (script, p.returncode, p.stdout[-400:], p.stderr[-2000:])
    checks += 1
    return p


def nvim_session(d, src, chunks, binary_mode=False):
    """Type `chunks` into an interactive nvim on a private PTY.

    nvim run from -c/-s at startup joins every change into one undo
    block, so undo/redo can only be referenced interactively. An ESC is
    followed by a pause longer than nvim's 'ttimeoutlen' (50 ms) so it
    is not read as the start of a Meta key.
    """
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 200, 0, 0))
    cmd = [nvim, '-u', 'NONE', '-i', 'NONE', '-n'] + (['-b'] if binary_mode else [])
    # Keys typed before the main loop runs are startup typeahead and get
    # merged into one undo block too; a zero timer fires only once nvim
    # is waiting for input, so its ready file gates the typing.
    ready = d / 'ref-ready'
    ready.unlink(missing_ok=True)
    cmd += ['-c', 'set nofixeol sol',
            '-c', f"call timer_start(0, {{-> writefile([], '{ready}')}})", str(src)]
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, cwd=d,
                            env={**os.environ, 'TERM': 'xterm'}, start_new_session=True)
    os.close(slave)
    done = threading.Event()

    def drain():
        while not done.is_set():
            if select.select([master], [], [], 0.05)[0]:
                try:
                    if not os.read(master, 65536):
                        break
                except OSError:
                    break
    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        deadline = time.monotonic() + 20
        while not ready.exists():
            assert time.monotonic() < deadline and proc.poll() is None, 'nvim did not start'
            time.sleep(0.01)
        for chunk in chunks:
            for i, part in enumerate(chunk.split(ESC)):
                if i:
                    os.write(master, ESC)
                    time.sleep(0.12)
                if part:
                    os.write(master, part)
        proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        done.set()
        reader.join()
        os.close(master)


def reference(d, data, keys=None, ex=None, binary_mode=False):
    """Bytes nvim writes for the same keystrokes or ex commands, or None."""
    global ref_checks, skipped
    if not nvim:
        skipped += 1
        return None
    src = d / 'ref-in'
    out = d / 'ref-out'
    src.write_bytes(data)
    out.unlink(missing_ok=True)
    body = keys if keys is not None else b''.join(b':' + c.encode() + CR for c in ex)
    nvim_session(d, src, [body, ESC + b':w! ' + bytes(out) + CR + b':q!' + CR],
                 binary_mode=binary_mode)
    ref_checks += 1
    return out.read_bytes()


def keys_case(d, name, data, keys, want, binary_mode=False, compare=True):
    f = d / (name + '.txt')
    k = d / (name + '.keys')
    out = d / (name + '.out')
    f.write_bytes(data)
    k.write_bytes(keys + b':w ' + bytes(out) + CR + b':q!' + CR)
    flags = '-b ' if binary_mode else ''
    shell(f'vi {flags}--keys "$1" "$2"', k, f)
    got = out.read_bytes()
    assert got == want, (name, keys, got, want)
    assert f.read_bytes() == data, (name, 'input changed without :w')
    if compare:
        ref = reference(d, data, keys=keys, binary_mode=binary_mode)
        assert ref is None or ref == got, (name, 'nvim differs', keys, got, ref)


def ex_case(d, name, data, cmds, want, rc=0, err=None, compare=True, script=False,
            binary_mode=False):
    """Ex commands as -c arguments, or with script=True as a -s file.
    Like vi, a failing command does not stop the later ones, so the
    final :w still writes; `want` is then the unchanged text."""
    f = d / (name + '.txt')
    out = d / (name + '.out')
    f.write_bytes(data)
    out.unlink(missing_ok=True)
    if script:
        (d / (name + '.ex')).write_text(''.join(c + '\n' for c in cmds)
                                        + f'w {out}\nq!\n')
        p = shell('vi %s-s "$1" "$2"' % ('-b ' if binary_mode else ''),
                  d / (name + '.ex'), f, rc=rc)
    else:
        argv = ['-b'] if binary_mode else []
        for c in cmds:
            argv += ['-c', c]
        p = shell('vi "$@"', *argv, '-c', f'w {out}', '-c', 'q!', f, rc=rc)
    if err is not None:
        assert err in p.stderr, (name, p.stderr)
    if want is None:   # refused before loading: nothing may be written
        assert not out.exists(), (name, 'wrote despite refusing the file')
        return
    got = out.read_bytes()
    assert got == want, (name, cmds, got, want)
    if compare:
        ref = reference(d, data, ex=cmds, binary_mode=binary_mode)
        assert ref is None or ref == got, (name, 'nvim differs', cmds, got, ref)


abc = b'a\nb\nc\nd\n'
with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)

    # Inclusive visual endpoints cover whole UTF-8 characters, in either
    # direction, including yanks which are subsequently put back.
    for label, char in [('two', 'é'), ('three', '界'), ('four', '🙂')]:
        u = char.encode()
        keys_case(d, 'visual-end-' + label, b'a' + u + b'\n', b'v$d', b'\n')
        keys_case(d, 'visual-one-' + label, u + b'x\n', b'vd', b'x\n')
        keys_case(d, 'visual-x-' + label, u + b'x\n', b'vx', b'x\n')
        keys_case(d, 'visual-reverse-' + label, b'a' + u + b'\n', b'$v0d', b'\n')
        keys_case(d, 'visual-yank-' + label, b'a' + u + b'z\n', b'vly0P', b'a' + u + b'a' + u + b'z\n')
        keys_case(d, 'visual-yank-end-' + label, b'a' + u + b'\n', b'v$y0P', b'a' + u + b'a' + u + b'\n')
        keys_case(d, 'visual-no-eol-' + label, b'a' + u, b'v$d', b'', compare=False)

    # --- the reported defect: dd after G must keep deleting ---
    keys_case(d, 'g-dd-1', abc, b'Gdd', b'a\nb\nc\n')
    keys_case(d, 'g-dd-2', abc, b'Gdddd', b'a\nb\n')
    keys_case(d, 'g-dd-3', abc, b'Gdddddd', b'a\n')
    keys_case(d, 'g-dd-all', abc, b'Gdddddddd', b'')
    keys_case(d, 'g-dd-past-empty', abc, b'G' + b'dd' * 9, b'')
    keys_case(d, 'g-dot', abc, b'Gdd..', b'a\n')
    # Motions after the deletion act on the new last line.
    keys_case(d, 'g-dd-k', abc, b'Gddkdd', b'a\nc\n')
    keys_case(d, 'g-dd-j-noop', abc, b'Gddjdd', b'a\nb\n')
    keys_case(d, 'g-dd-insert', abc, b'Gddix' + ESC, b'a\nb\nxc\n')
    keys_case(d, 'g-dd-x', b'ab\ncd\nef\n', b'Gddx', b'ab\nd\n')
    keys_case(d, 'g-dd-w-x', b'ab\ncd\nef\n', b'Gddwx', b'ab\nc\n')
    keys_case(d, 'g-dd-w-x-noeol', b'ab\ncd\nef', b'Gddwx', b'ab\nc')
    keys_case(d, 'g-dd-p', abc, b'Gddp', b'a\nb\nc\nd\n')
    keys_case(d, 'g-dd-P', abc, b'GddP', b'a\nb\nd\nc\n')
    # ESC keeps the cursor on its line, so the next edit hits that line.
    keys_case(d, 'o-esc-empty-line', b'a\n', b'o' + ESC + b'ix' + ESC, b'a\nx\n')
    keys_case(d, 'i-esc-col0', b'ab\ncd\n', b'ji' + ESC + b'x', b'ab\nd\n')
    keys_case(d, 'append-esc', b'ab\n', b'$ax' + ESC + b'x', b'ab\n')
    # A trailing empty line is a real line for G.
    keys_case(d, 'g-empty-last', b'a\nb\n\n', b'Gdd', b'a\nb\n')
    keys_case(d, 'g-empty-last-2', b'a\n\n\n', b'Gdddd', b'a\n')
    keys_case(d, 'j-past-end', b'a\nb\n', b'jjjjdd', b'a\n')
    keys_case(d, 'g-first-nonblank', b'a\n  b\n', b'Gx', b'a\n  \n')
    keys_case(d, 'dd-first-nonblank', b'a\n  bc\n  de\n', b'jddx', b'a\n  e\n')

    # --- one-line and empty files ---
    keys_case(d, 'one-line', b'only\n', b'dd', b'')
    keys_case(d, 'one-line-twice', b'only\n', b'dddd', b'')
    keys_case(d, 'one-line-noeol', b'only', b'dd', b'')
    keys_case(d, 'empty', b'', b'dd', b'')
    keys_case(d, 'empty-g', b'', b'Gddx', b'')
    keys_case(d, 'single-newline', b'\n', b'dd', b'')
    # vi models the empty buffer as zero bytes and writes typed text as
    # typed; nvim keeps an end-of-line flag and would write "y\n".
    keys_case(d, 'empty-then-insert', b'x\n', b'ddiy' + ESC, b'y', compare=False)

    # --- final newline state ---
    keys_case(d, 'noeol-g-dd', b'a\nb\nc', b'Gdd', b'a\nb')
    keys_case(d, 'noeol-g-dd-dd', b'a\nb\nc', b'Gdddd', b'a')
    keys_case(d, 'noeol-mid-dd', b'a\nb\nc', b'jdd', b'a\nc')
    keys_case(d, 'noeol-yy-p', b'a\nb', b'jyyp', b'a\nb\nb')
    keys_case(d, 'noeol-dd-p', b'a\nb\nc', b'Gddp', b'a\nb\nc')
    keys_case(d, 'noeol-2dd-end', b'a\nb\nc', b'j2dd', b'a')
    # Missing EOL can expose a zero-byte last line after a delete. It
    # remains a real line in memory even though a save cannot encode that
    # distinction. Exercise snapshots, motion, counts, yank and insertion.
    keys_case(d, 'noeol-empty-tail-repeat', b'a\n\nb', b'Gdddd', b'a')
    keys_case(d, 'noeol-empty-tail-undo', b'a\n\nb', b'Gddddu', b'a\n')
    keys_case(d, 'noeol-empty-tail-redo', b'a\n\nb', b'Gddddu' + CTRL_R, b'a')
    keys_case(d, 'noeol-empty-tail-undo-cursor', b'a\n\nb', b'Gdddduix' + ESC, b'a\nx')
    keys_case(d, 'noeol-empty-tail-down', b'a\n\nb', b'Gddkjdd', b'a')
    keys_case(d, 'noeol-empty-tail-count', b'a\n\nb', b'Gddk2dd', b'')
    keys_case(d, 'noeol-empty-tail-put', b'a\n\nb', b'Gddp', b'a\n\nb')
    keys_case(d, 'noeol-empty-tail-put-before', b'a\n\nb', b'Gddkp', b'a\nb\n')
    keys_case(d, 'noeol-empty-tail-yank', b'a\n\nb', b'Gddk2yyGp', b'a\n\na\n')
    keys_case(d, 'noeol-empty-tail-insert', b'a\n\nb', b'Gddix' + ESC, b'a\nx')
    keys_case(d, 'noeol-put-blank-tail-delete', b'a\n\nb', b'2yyGpGdd', b'a\n\nb\na')
    keys_case(d, 'noeol-empty-tail-count-before', b'a\n\nb', b'Gddkdd', b'')
    keys_case(d, 'noeol-empty-tail-count-undo', b'a\n\nb',
              b'Gddk2dduGdd', b'a')
    keys_case(d, 'noeol-only-blank-tail-undo', b'\nb', b'Gddddu', b'')
    keys_case(d, 'noeol-empty-tail-save', b'a\n\nb',
              b'Gdd:w ' + bytes(d / 'intermediate') + CR + b'dd', b'a', compare=False)
    assert (d / 'intermediate').read_bytes() == b'a\n'

    # --- counts ---
    keys_case(d, 'count-3dd', b'1\n2\n3\n4\n5\n', b'j3dd', b'1\n5\n')
    keys_case(d, 'count-d3d', b'1\n2\n3\n4\n5\n', b'jd3d', b'1\n5\n')
    keys_case(d, 'count-2d2d', b'1\n2\n3\n4\n5\n6\n', b'2d2d', b'5\n6\n')
    keys_case(d, 'count-clamped', abc, b'jj3dd', b'a\nb\n')
    keys_case(d, 'count-last-line-fails', abc, b'G2dd', abc)
    keys_case(d, 'count-after-g-dd-fails', abc, b'Gdd2dd', b'a\nb\nc\n')
    keys_case(d, 'count-large', abc, b'99dd', b'')
    keys_case(d, 'count-dot', b'1\n2\n3\n4\n5\n6\n7\n', b'2dd.', b'5\n6\n7\n')
    keys_case(d, 'count-dot-override', b'1\n2\n3\n4\n5\n6\n7\n', b'2dd3.', b'6\n7\n')
    keys_case(d, 'count-NG', b'1\n2\n3\n4\n', b'3Gdd', b'1\n2\n4\n')
    keys_case(d, 'count-NG-past', b'1\n2\n3\n4\n', b'9Gdd', b'1\n2\n3\n')
    keys_case(d, 'count-10j', b''.join(b'%d\n' % i for i in range(12)), b'10jdd',
              b''.join(b'%d\n' % i for i in range(12) if i != 10))
    keys_case(d, 'count-x', b'abcdef\n', b'l3x', b'aef\n')
    keys_case(d, 'count-x-clamped', b'abc\nd\n', b'l9x', b'a\nd\n')
    keys_case(d, 'count-yy-p', b'1\n2\n3\n', b'2yyGp', b'1\n2\n3\n1\n2\n')
    keys_case(d, 'count-p', b'1\n2\n', b'yy3p', b'1\n1\n1\n1\n2\n')
    # :d _ (black hole) leaves the register from yy for the put.
    keys_case(d, 'blackhole-keeps-register', b'1\n2\n3\n', b'yy:2d _' + CR + b'p',
              b'1\n3\n1\n')
    keys_case(d, 'ex-d-fills-register', b'1\n2\n3\n', b'yy:2d' + CR + b'p',
              b'1\n3\n2\n')

    # --- undo / redo ---
    keys_case(d, 'undo-g-dd', abc, b'Gddu', abc)
    keys_case(d, 'undo-all', abc, b'Gdddddddduuuu', abc)
    keys_case(d, 'undo-redo', abc, b'Gdddddduu' + CTRL_R, b'a\nb\n')
    keys_case(d, 'undo-then-dd', abc, b'Gdddduudd', b'a\nb\nc\n')
    keys_case(d, 'undo-count', abc, b'Gdddddd2u', b'a\nb\nc\n')
    keys_case(d, 'redo-count', abc, b'Gdddddd3u2' + CTRL_R, b'a\nb\n')
    keys_case(d, 'redo-then-dd', abc, b'Gddu' + CTRL_R + b'dd', b'a\nb\n')
    keys_case(d, 'undo-3dd-cursor', b'1\n2\n3\n4\n5\n', b'j3dduix' + ESC,
              b'1\nx2\n3\n4\n5\n')
    keys_case(d, 'undo-empty-noop', abc, b'u' + CTRL_R + b'dd', b'b\nc\nd\n')

    # --- binary and UTF-8 bytes ---
    blob = b'\x00\x01\n\xff\xfe\n\x00\n'
    keys_case(d, 'binary-g-dd', blob, b'Gdddd', b'\x00\x01\n', binary_mode=True)
    keys_case(d, 'binary-g-dd-noeol', b'\x00\n\x01', b'Gdd', b'\x00', binary_mode=True)
    utf = 'α\nβγ\nδ\n'.encode()
    keys_case(d, 'utf8-g-dd', utf, b'Gdddd', 'α\n'.encode())
    keys_case(d, 'utf8-x', 'aé€b\n'.encode(), b'lx', 'a€b\n'.encode())
    keys_case(d, 'utf8-2x', 'aé€b\n'.encode(), b'l2x', b'ab\n')
    keys_case(d, 'utf8-dollar-x', 'abé\n'.encode(), b'$x', b'ab\n')
    keys_case(d, 'utf8-l-h-x', 'é€ü\n'.encode(), b'llhx', 'éü\n'.encode())
    keys_case(d, 'utf8-p-charwise', 'é€\n'.encode(), b'xp', '€é\n'.encode())

    # --- ex path: :d with ranges and counts ---
    ex_case(d, 'ex-d', abc, ['d'], b'b\nc\nd\n')
    ex_case(d, 'ex-dollar-d', abc, ['$d'], b'a\nb\nc\n')
    ex_case(d, 'ex-dollar-d-repeat', abc, ['$d', '$d', '$d'], b'a\n')
    ex_case(d, 'ex-goto-d-repeat', abc, ['$', 'd', 'd', 'd'], b'a\n')
    ex_case(d, 'ex-goto-d-all', abc, ['$', 'd', 'd', 'd', 'd', 'd'], b'')
    ex_case(d, 'ex-range', abc, ['2,3d'], b'a\nd\n')
    ex_case(d, 'ex-percent', abc, ['%d'], b'')
    ex_case(d, 'ex-count', abc, ['2d 2'], b'a\nd\n')
    ex_case(d, 'ex-count-clamped', abc, ['3d 9'], b'a\nb\n')
    ex_case(d, 'ex-offsets', abc, ['$-1,$d'], b'a\nb\n')
    ex_case(d, 'ex-dot-plus', abc, ['2', '.,.+1d'], b'a\nd\n')
    ex_case(d, 'ex-delete-word', abc, ['2delete'], b'a\nc\nd\n')
    ex_case(d, 'ex-del-abbrev', abc, ['1,2del'], b'c\nd\n')
    ex_case(d, 'ex-noeol', b'a\nb\nc', ['$d'], b'a\nb')
    ex_case(d, 'ex-noeol-empty-tail', b'a\n\nb', ['$d', '$', 'd'], b'a')
    ex_case(d, 'ex-noeol-empty-tail-count', b'a\n\nb', ['$d', '1d 2'], b'')
    ex_case(d, 'ex-noeol-empty-tail-undo', b'a\n\nb', ['$d', 'd', 'undo'], b'a\n')
    ex_case(d, 'ex-noeol-empty-tail-redo', b'a\n\nb', ['$d', 'd', 'undo', 'redo'], b'a')
    ex_case(d, 'ex-empty-d', b'', ['d'], b'')
    ex_case(d, 'ex-undo', abc, ['$d', '$d', 'undo'], b'a\nb\nc\n')
    ex_case(d, 'ex-undo-redo', abc, ['$d', '$d', 'u', 'u', 'redo'], b'a\nb\nc\n')
    ex_case(d, 'ex-goto-past-end', abc, ['99', 'd'], b'a\nb\nc\n')
    ex_case(d, 'ex-binary-d', blob, ['$d'], b'\x00\x01\n\xff\xfe\n', binary_mode=True)
    ex_case(d, 'ex-binary-refused', blob, ['$d'], None, rc=1, compare=False)
    # Invalid ranges fail, change nothing, and set the exit status.
    ex_case(d, 'ex-invalid-range', abc, ['5d'], abc, rc=1, err=b'E16: Invalid range')
    ex_case(d, 'ex-backwards', abc, ['3,2d'], abc, rc=1, err=b'E493: Backwards range',
            compare=False)  # nvim prompts to swap the range
    ex_case(d, 'ex-zero-count', abc, ['d 0'], abc, rc=1, err=b'E939: Positive count')
    ex_case(d, 'ex-trailing', abc, ['d x y'], abc, rc=1, err=b'E488: Trailing characters')
    ex_case(d, 'ex-register', abc, ['d x'], b'b\nc\nd\n')
    ex_case(d, 'ex-register-count', abc, ['2d a 2'], b'a\nd\n')
    # vi rejects a range on :w rather than silently writing every line.
    ex_case(d, 'ex-range-on-write', abc, ['1,2w'], abc, rc=1,
            err=b'E481: No range allowed', compare=False)
    ex_case(d, 'ex-negative', abc, ['1-5d'], abc, rc=1, err=b'E16: Invalid range')
    ex_case(d, 'ex-script-d', abc, ['$', 'd', 'd'], b'a\nb\n', script=True)

    # --- 250 actual deletes after G: exact remaining bytes ---
    lines = [b'line %04d %s\n' % (i, hashlib.sha256(b'%d' % i).hexdigest()[:24].encode())
             for i in range(1000)]
    big = b''.join(lines)
    want = b''.join(lines[:750])
    keys_case(d, 'g-250dd', big, b'G' + b'dd' * 250, want)
    got = (d / 'g-250dd.out').read_bytes()
    assert len(got) == len(big) - sum(map(len, lines[750:])) and got.count(b'\n') == 750
    assert hashlib.sha256(got).hexdigest() == hashlib.sha256(want).hexdigest()
    keys_case(d, 'g-250dd-undo', big, b'G' + b'dd' * 250 + b'u' * 250, big)
    ex_case(d, 'ex-250d', big, ['$'] + ['d'] * 250, want, script=True)
    ex_case(d, 'ex-250-range', big, ['751,$d'], want)

    # --- repeated calls in one shell: no leaked count/operator/undo ---
    # r1 ends mid-command ("3d"); a leaked operator would swallow r2's j
    # and its x would hit line 1. r2's leading u must find no history.
    (d / 'r1.keys').write_bytes(b'Gdd:w' + CR + b'3d')
    (d / 'r2.keys').write_bytes(b'jux:w' + CR + b':q' + CR)
    p = shell('''
# Count this shell directly: command substitution races the parent pipe cleanup.
fds() { local f; fd_count=0; for f in /proc/$BASHPID/fd/*; do fd_count=$((fd_count+1)); done; }
fds; before=$fd_count
for i in 1 2 3; do
  printf 'a\\nb\\nc\\nd\\n' > "$2"; printf 'a\\nb\\nc\\nd\\n' > "$4"
  vi --keys "$1" "$2"; vi --keys "$3" "$4"
done
vi -c '$d' -c "w $5" -c 'q!' "$4"
vi -c 'd 0' "$4" 2>/dev/null && exit 9
fds; after=$fd_count
[[ $before == "$after" ]] || { echo "fd leak $before $after"; exit 8; }
type -t vi
''', d / 'r1.keys', d / 'r1.txt', d / 'r2.keys', d / 'r2.txt', d / 'r3.out')
    assert p.stdout == b'builtin\n', p.stdout
    assert (d / 'r1.txt').read_bytes() == b'a\nb\nc\n', (d / 'r1.txt').read_bytes()
    assert (d / 'r2.txt').read_bytes() == b'a\n\nc\nd\n', (d / 'r2.txt').read_bytes()
    assert (d / 'r3.out').read_bytes() == b'a\n\nc\n', (d / 'r3.out').read_bytes()

    # --- save failure leaves the target and no temporary behind ---
    ro = d / 'ro'
    ro.mkdir()
    (ro / 'f').write_bytes(abc)
    if os.geteuid() != 0:
        ro.chmod(0o555)
        p = shell('vi -c "\\$d" -c "w" -c "q!" "$1"', ro / 'f', rc=1)
        assert b'E212: write failed' in p.stderr, p.stderr
        ro.chmod(0o755)
        assert sorted(x.name for x in ro.iterdir()) == ['f'] and (ro / 'f').read_bytes() == abc
    else:
        skipped += 1
    p = shell('vi -c "\\$d" -c "w $1/missing/out" "$2"', d, d / 'r2.txt', rc=1)
    assert b'E212: write failed' in p.stderr, p.stderr
    assert not list(d.glob('missing*')) and not list(d.glob('*.tmp.*'))

    # --- usage errors ---
    shell('vi --keys', rc=2)
    shell('vi --keys "$1"', d / 'no-such-keys', rc=1)
    shell('vi -c', rc=2)
    p = shell('vi ' + ' '.join(['-c 1'] * 17) + ' "$1"', d / 'r2.txt', rc=2)
    assert b'too many' in p.stderr, p.stderr
    (d / 'nul').write_bytes(b'a\0b\n')
    shell('vi --keys "$1" "$2"', d / 'r2.keys', d / 'nul', rc=1)

print(f'opus-vi-dd: {checks} checks, {ref_checks} nvim reference comparisons, '
      f'{skipped} skipped')
