#!/usr/bin/env python3
"""Injected client regressions; does not qualify kernel authentication."""
from pathlib import Path
import json,re,subprocess,sys
from guest import guard,save,entrypoint,digest

def main():
    guard()
    assets=Path(sys.argv[1]);output=Path(sys.argv[2]);observations=[]
    def require(ok,why):
        if not ok:raise RuntimeError(why)
    def run(name,args):
        result=subprocess.run([str(assets/name),*args],capture_output=True,timeout=10)
        observations.append(dict(name=name,sha256=digest(assets/name),status=result.returncode,stdout_hex=result.stdout.hex(),stderr_hex=result.stderr.hex()))
        save(output,dict(result='ERROR',scope='injected native controls only; no authentication or topic coverage',observations=observations))
        return result
    for kind in ('current', 'baseline'):
        result = run('client-regressions-' + kind, ['--injected-regressions'])
        rows = result.stdout.decode().splitlines()
        require(len(rows) == 17, 'incomplete injected case inventory')
        for i in range(8):
            expected = 0 if i <= 2 else 1
            actual = expected if kind == 'current' else 0
            require(re.fullmatch(r'audit case=' + str(i) + ' result=' + str(actual) +
                                 ' expected=' + str(expected) + r' writes=[0-1] prints=[0-1]', rows[i]),
                    'audit observer/control mismatch')
            expected = int(i in (0, 5))
            actual = expected if kind == 'current' else int(i not in (1, 2))
            require(rows[8+i] == f'wait case={i} result={actual} expected={expected} waits={2 if i == 5 else 1}',
                    'wait observer/control mismatch')
        fails = 0 if kind == 'current' else 11
        require(result.returncode == (0 if kind == 'current' else 1) and
                re.fullmatch(r'client-regressions cases=16 checks=[0-9]+ failures=' + str(fails) + r' injected=yes', rows[-1]),
                'injected fixture result mismatch')
        if kind == 'current':
            require(not result.stderr, 'current fixture diagnostics')
        else:
            require(len(result.stderr.decode().splitlines()) == 11 and
                    all(x.startswith('FAIL line=') for x in result.stderr.decode().splitlines()),
                    'baseline negative control did not reach exactly the known defects')
    result = run('release-regressions', ['--injected-regressions'])
    require(result.returncode == 0 and not result.stderr and result.stdout ==
            b'release-regressions wait=8 handoff=6 argv=8 phc=10 checks=49 failures=0 injected=yes\n',
            'release helper regressions failed')
    result = run('phc-record-regressions', ['--parser-controls'])
    require(result.returncode == 0 and not result.stderr and result.stdout ==
            b'phc-record-regressions checks=60 failures=0 parser_only=yes\n',
            'explicit PHC record parser controls failed')
    for kind in ('current', 'baseline'):
        result = run('login-drop-' + kind, ['--injected-regressions'])
        rows = result.stdout.decode().splitlines()
        require(len(rows) == 10, 'incomplete login-drop control inventory')
        for i in range(9):
            prefix = 0 if i == 8 else i if 1 <= i <= 5 else 5
            returned = int(kind == 'baseline' and i != 0)
            status = -1 if returned else 126 if i else 0
            require(rows[i] == f'drop case={i} prefix={prefix} returned={returned} exit={status} exec={int(i == 0)}',
                    'login-drop source behavior differs')
        failures = 0 if kind == 'current' else 16
        require(rows[-1] == f'login-drop-regressions cases=9 failures={failures} injected=yes' and
                result.returncode == (0 if kind == 'current' else 1), 'login-drop result differs')
        errors = result.stderr.decode().splitlines()
        require(len(errors) == failures and all(x.startswith('FAIL line=') for x in errors),
                'login-drop negative control inventory differs')
    save(output,dict(result='PASS',scope='injected native controls only; no authentication or topic coverage',observations=observations))
    return 0

if __name__=='__main__':entrypoint(main)
