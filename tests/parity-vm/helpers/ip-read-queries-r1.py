#!/usr/bin/python3
"""Additional ip query regressions; run only in a disposable VM user/net namespace."""
import importlib.util
import json
import os
import sys

base = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('ip_fixture', os.path.join(base, 'mig-w1-ip.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
L = fixture.L


def body():
    fixture.setup_ns()
    L.seed(fixture.SHOW_SEED + [["rule", "add", "fwmark", "0x12/0xff", "table", "100", "priority", "700"]])
    for family in ("-4", "-6"):
        args = [family, "-j", "route", "show", "table", "all"]
        rc, out, err = L.cand_ip(args)
        rr, ref, re = L.ref_ip(args)
        L.check("route family status " + family, rc == rr == 0, repr((rc, err, rr, re)))
        if rc == rr == 0:
            got = {(r.get('dst'), r.get('dev'), r.get('table', 'main')) for r in json.loads(out)}
            expected = {(r.get('dst'), r.get('dev'), r.get('table', 'main')) for r in json.loads(ref)}
            L.check("route family " + family, got == expected, repr((got, expected)))
    for args in (["rule", "show"], ["-j", "rule", "show"]):
        rc, out, err = L.cand_ip(args)
        rr, ref, re = L.ref_ip(args)
        L.check("rule status " + repr(args), rc == rr == 0, repr((rc, err, rr, re)))
        if rc == rr == 0:
            got = json.loads(out) if '-j' in args else out.splitlines()
            expected = json.loads(ref) if '-j' in args else ref.splitlines()
            L.check("rule masks " + repr(args), got == expected, repr((got, expected)))
    return {}

L.in_netns(body)
sys.exit(L.finish('ip-read-queries-r1'))
