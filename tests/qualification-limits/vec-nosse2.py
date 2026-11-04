#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run only in a genuine/emulated 32-bit CPU environment without SSE2."""
import argparse
from decimal import Decimal
import json
from guest import clean_env, digest, entrypoint, guard, require_bash_5320, run, save


def main():
    p = argparse.ArgumentParser()
    p.add_argument("shell32"); p.add_argument("module32"); p.add_argument("cpu_probe32"); p.add_argument("output")
    a = p.parse_args(); guard()
    bash_version = require_bash_5320(a.shell32)
    cpu = run([a.cpu_probe32])
    if cpu["status"] != 0 or cpu["stderr_hex"]:
        save(a.output,dict(result="ERROR",reason="non-SSE2 prerequisite missing",cpu=cpu)); return 125
    flags = json.loads(bytes.fromhex(cpu["stdout_hex"]))
    if flags != dict(pointer_bits=32,sse2=0,avx=0,avx2=0,sse2_sigill=1): raise RuntimeError("CPU control disagrees")
    script = ['set -eu', '[[ $(type -t vec || :) != builtin ]] || exit 125',
              'enable -f "$1" vec || exit 125', 'vec backend']
    oracle = []
    for typ in ("i32","u32","i64","u64","f32","f64"):
        for n in (1,2,3,4,5,7,8,9,15,16,17,31,32,33,63,64,65):
            aa = [(i*17+3)%41-20 for i in range(n)]
            bb = [(i*11+7)%29-14 for i in range(n)]
            if typ.startswith("u"):
                aa = [v+20 for v in aa]; bb = [v+14 for v in bb]
            if typ.startswith("f"):
                aa = [Decimal(v)/2 for v in aa]; bb = [Decimal(v)/2 for v in bb]
            script += ['a=('+' '.join(map(str,aa))+')', 'b=('+' '.join(map(str,bb))+')',
                       'vec from-array -T '+typ+' a -h ha', 'vec from-array -T '+typ+' b -h hb',
                       'vec sum "$ha"; vec min "$ha"; vec max "$ha"; vec dot "$ha" "$hb"',
                       'vec free "$ha"; vec free "$hb"']
            oracle += list(map(Decimal,(sum(aa),min(aa),max(aa),sum(x*y for x,y in zip(aa,bb)))))
    rows = []
    for backend in (None,"auto","scalar","sse2","avx2"):
        env = clean_env()
        if backend is not None: env["BASHVEC_BACKEND"] = backend
        r = run([a.shell32,"--noprofile","--norc","-c","\n".join(script),"qualification",a.module32],timeout=35,env=env)
        values = bytes.fromhex(r["stdout_hex"]).decode("ascii").splitlines()
        numeric = None
        try: numeric = list(map(Decimal,values[1:]))
        except ArithmeticError: pass
        r.update(backend=backend, matches=bool(values and values[0] == "scalar" and numeric == oracle))
        rows.append(r)
    result = "PASS" if all(r["status"] == 0 and not r["stderr_hex"] and r["matches"] for r in rows) else "FAIL"
    # An executable that could not load/start is an environment error, not a vec failure.
    if any(r["status"] in (125,126,127) for r in rows): result = "ERROR"
    save(a.output,dict(scope="new i686 shell/module, not x86-64 release evidence",result=result,
                       bash_version=bash_version,
                       binaries={x:digest(x) for x in (a.shell32,a.module32,a.cpu_probe32)},cpu=cpu,
                       exact_assertions_per_backend=len(oracle),observations=rows))
    return {"PASS":0,"FAIL":1,"ERROR":125}[result]


if __name__ == "__main__": entrypoint(main)
