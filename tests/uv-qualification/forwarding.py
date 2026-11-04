#!/usr/bin/env python3
"""Run only in a disposable VM: forwarding checks for built-in or loaded uv.

Usage: forwarding.py static BASH | forwarding.py dynamic BASH UV_SO
Static mode requires an absent /usr/lib/bash-os/libexec/uv/uv and permission
inside the guest to create it. Dynamic mode copies UV_SO into a temporary
package tree. Each assertion fails closed if uv cannot be selected.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) not in (3, 4) or sys.argv[1] not in ('static', 'dynamic') or (sys.argv[1] == 'dynamic') != (len(sys.argv) == 4):
    raise SystemExit(__doc__)
mode, bash = sys.argv[1], str(Path(sys.argv[2]).resolve())
helper_text = '''#!/bin/sh
case "$1" in
  args) shift; for a do printf '[%s]\\n' "$a"; done ;;
  env) printf 'exported=%s\\nplain=%s\\nprefix=%s\\n' "${UVQ_EXPORTED-unset}" "${UVQ_PLAIN-unset}" "${UVQ_PREFIX-unset}" ;;
  status) exit "$2" ;;
  *) exit 91 ;;
esac
'''
with tempfile.TemporaryDirectory(prefix='uv-qualification-') as tmp:
    root = Path(tmp)
    if mode == 'dynamic':
        module = root / 'lib/bash-os/loadables/uv.so'
        module.parent.mkdir(parents=True)
        shutil.copyfile(sys.argv[3], module)
        helper = root / 'lib/bash-os/libexec/uv/uv'
        init = 'enable -f "$1" uv || exit 98; [[ $(type -t uv) == builtin ]] || exit 99; '
        shell_args = [str(module)]
    else:
        helper = Path('/usr/lib/bash-os/libexec/uv/uv')
        init = '[[ $(type -t uv) == builtin ]] || exit 99; '
        shell_args = []
    helper.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents replacing any guest installation.
    with helper.open('x') as f:
        f.write(helper_text)
    helper.chmod(0o755)
    try:
        cases = [
            ('uvq-forward-args', "uv args alpha '' 'two words' 'dollar$sign' '*'; echo status=$?", '[alpha]\n[]\n[two words]\n[dollar$sign]\n[*]\nstatus=0\n'),
            ('uvq-forward-env', "export UVQ_EXPORTED=visible; UVQ_PLAIN=hidden; UVQ_PREFIX=temporary uv env; echo status=$?", 'exported=visible\nplain=unset\nprefix=temporary\nstatus=0\n'),
            ('uvq-forward-status', 'uv status 0; echo s0=$?; uv status 7; echo s7=$?; uv status 200; echo s200=$?', 's0=0\ns7=7\ns200=200\n'),
        ]
        env = {k: v for k, v in os.environ.items() if not k.startswith('UVQ_')}
        for case_id, script, expected in cases:
            result = subprocess.run([bash, '--noprofile', '--norc', '-c', init + script, '_', *shell_args], env=env, capture_output=True, text=True, timeout=30)
            if result.returncode != 0 or result.stdout != expected or result.stderr:
                raise SystemExit(f'{case_id}: FAIL status={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
            print(f'{case_id}: PASS')
    finally:
        helper.unlink()
