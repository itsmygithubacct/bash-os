#!/usr/bin/python3
"""Guest-only SQLite locking probe. Never import or run on the authoring host."""
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

HOME = Path(os.environ['HOME'])
ROOT = Path.cwd()
RAW = HOME / 'sqlite-lock-observations.json'
A = r'''
type -t sqlite > a-type
sqlite open candidate.db -h db; printf '%s\n' "$?" > a-open
sqlite exec "$db" 'BEGIN IMMEDIATE'; printf '%s\n' "$?" > a-begin
sqlite exec "$db" "INSERT INTO t VALUES (10, 'writer-a')"; printf '%s\n' "$?" > a-write
printf 'ready\n' > a-ready
IFS= read -r release
sqlite exec "$db" 'ROLLBACK'; printf '%s\n' "$?" > a-rollback
sqlite close "$db"; printf '%s\n' "$?" > a-close
'''
B = r'''
type -t sqlite > b-type
sqlite open candidate.db -h db; printf '%s\n' "$?" > b-open
sqlite exec "$db" 'BEGIN IMMEDIATE'; rc=$?; printf '%s\n' "$rc" > b-begin
if [ "$rc" -eq 0 ]; then
  sqlite exec "$db" "INSERT INTO t VALUES (20, 'writer-b')"; printf '%s\n' "$?" > b-write
  sqlite exec "$db" 'ROLLBACK'; printf '%s\n' "$?" > b-rollback
fi
sqlite close "$db"; printf '%s\n' "$?" > b-close
'''


def save(data):
    RAW.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def seed(path):
    db = sqlite3.connect(str(path), timeout=0)
    db.execute('CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
    db.execute("INSERT INTO t VALUES (1, 'seed')")
    db.commit()
    db.close()


def lock_control():
    path = ROOT / 'control.db'
    seed(path)
    a = sqlite3.connect(str(path), timeout=0)
    b = sqlite3.connect(str(path), timeout=0)
    try:
        a.execute('BEGIN IMMEDIATE')
        a.execute("INSERT INTO t VALUES (10, 'writer-a')")
        try:
            b.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as e:
            code = getattr(e, 'sqlite_errorcode', None)
            if code != sqlite3.SQLITE_BUSY:
                raise RuntimeError('control did not return SQLITE_BUSY: ' + repr(e))
        else:
            raise RuntimeError('control second writer unexpectedly acquired lock')
        a.rollback()
        b.execute('BEGIN IMMEDIATE')
        b.execute("INSERT INTO t VALUES (20, 'control')")
        b.commit()
        rows = b.execute('SELECT id,value FROM t ORDER BY id').fetchall()
        if rows != [(1, 'seed'), (20, 'control')]:
            raise RuntimeError('control contents mismatch')
        return {'second_begin_sqlite_errorcode': code, 'post_release_rows': rows}
    finally:
        a.close()
        b.close()


def read_file(name):
    p = ROOT / name
    return p.read_text() if p.is_file() else None


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ('busy', 'no-lock'):
        raise RuntimeError('usage: helper candidate busy|no-lock')
    if os.geteuid() != 2000 or str(ROOT) != '/tmp/parity-case' or str(HOME) != '/tmp/parity-home':
        raise RuntimeError('unexpected guest identity or workspace')
    if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
        raise RuntimeError('QEMU guest guard failed')
    uuid = Path('/etc/bashos-parity-vm').read_text().strip()
    import re
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid):
        raise RuntimeError('guest identity guard failed')
    result = {'mode': sys.argv[2], 'guest_uuid': uuid, 'control': lock_control()}
    save(result)
    seed(ROOT / 'candidate.db')
    candidate = sys.argv[1]
    proc = subprocess.Popen([candidate, '--noprofile', '--norc', '-c', A], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        deadline = time.monotonic() + 8
        while not (ROOT / 'a-ready').is_file():
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('first writer did not reach ready barrier')
            time.sleep(.02)
        result['a_before_b'] = {k: read_file('a-' + k) for k in ('type', 'open', 'begin', 'write', 'ready')}
        save(result)
        if result['a_before_b'] != {'type': 'builtin\n', 'open': '0\n', 'begin': '0\n', 'write': '0\n', 'ready': 'ready\n'}:
            raise RuntimeError('first writer not established; inspect recorded candidate outputs')
        b = subprocess.run([candidate, '--noprofile', '--norc', '-c', B], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, start_new_session=True)
        result['b'] = {k: read_file('b-' + k) for k in ('type', 'open', 'begin', 'write', 'rollback', 'close')}
        result['b'].update(returncode=b.returncode, stdout_hex=b.stdout.hex(), stderr_hex=b.stderr.hex(),
                           a_alive_at_b_completion=proc.poll() is None)
        save(result)
        if b.returncode != 0 or result['b']['type'] != 'builtin\n' or result['b']['open'] != '0\n' or not result['b']['a_alive_at_b_completion']:
            raise RuntimeError('second writer or barrier incomplete')
        out, err = proc.communicate(b'release\n', timeout=8)
        result['a_after_b'] = {'returncode': proc.returncode, 'stdout_hex': out.hex(), 'stderr_hex': err.hex(),
                               'rollback': read_file('a-rollback'), 'close': read_file('a-close')}
        save(result)
        if proc.returncode != 0 or result['a_after_b']['rollback'] != '0\n' or result['a_after_b']['close'] != '0\n':
            raise RuntimeError('first writer cleanup incomplete')
        db = sqlite3.connect(str(ROOT / 'candidate.db'), timeout=0)
        try:
            result['integrity_check'] = db.execute('PRAGMA integrity_check').fetchall()
            result['rows_after_rollback'] = db.execute('SELECT id,value FROM t ORDER BY id').fetchall()
        finally:
            db.close()
        save(result)
        integrity = result['integrity_check'] == [('ok',)] and result['rows_after_rollback'] == [(1, 'seed')]
        begin = result['b']['begin']
        if begin not in ('0\n', '1\n') or result['b']['close'] != '0\n':
            raise RuntimeError('second writer status incomplete')
        if begin == '0\n' and (result['b']['write'] is None or result['b']['rollback'] is None):
            raise RuntimeError('second writer did not reach write and rollback')
        if sys.argv[2] == 'busy':
            # Candidate API exposes status and message, not SQLite numeric error codes.
            busy = begin == '1\n' and b'database is locked' in b.stderr
            print('busy=' + ('yes' if busy else 'no') + ' integrity=' + ('yes' if integrity else 'no'))
        else:
            print('both_begin=' + ('yes' if begin == '0\n' else 'no'))
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=3)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('CONTROL-INCOMPLETE: ' + repr(exc), file=sys.stderr)
        sys.exit(97)
