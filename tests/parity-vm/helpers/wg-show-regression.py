#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only regression for a single-response family lookup and wg show."""
import importlib.util
import os
import sys

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-wg.py")
spec = importlib.util.spec_from_file_location("wg_fixture", path)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

g = f.newdev()
g.set("wg0", priv=f.ALICE_PRIV, port=51820,
      peers=[{"public": f.BOB_PUB, "keepalive": 1}])
d = g.get("wg0")
f.L.check("independent kernel seed contains a peer with keepalive 1",
          len(d["peers"]) == 1 and d["peers"][0]["keepalive"] == 1, str(d))
rc, out, err = f.wg("show", "wg0")
f.L.check("single family reply completes and zero-state peer has singular keepalive",
          rc == 0 and "  allowed ips: (none)\n" in out
          and "  persistent keepalive: every 1 second\n" in out
          and "latest handshake:" not in out and "transfer:" not in out,
          "rc=%s out=%r err=%r" % (rc, out, err))
rc, out, err = f.wg("show", "no-such-wg")
f.L.check("missing device fails without printing device state", rc != 0 and not out,
          "rc=%s out=%r err=%r" % (rc, out, err))
sys.exit(f.L.finish("wg-show-regression"))
