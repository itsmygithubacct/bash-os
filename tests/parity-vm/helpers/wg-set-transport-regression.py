#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exercise family lookup, ACK/error handling and repeated peer updates in a guest."""
import importlib.util
import os
import sys

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mig-w1-wg.py")
spec = importlib.util.spec_from_file_location("wg_fixture", path)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
L = w.L

g = w.newdev()
key = w.b64(w.BOB_PUB)
rc, out, err = w.wg("set", "wg0", "listen-port", "23456", "peer", key,
                    "allowed-ips", "192.0.2.0/24")
d = g.get("wg0")
L.check("family response then set ACK and state", rc == 0 and d.get("port") == 23456
        and w.peer_of(d, w.BOB_PUB)["ips"] == {"192.0.2.0/24"}, "rc=%s err=%r state=%r" % (rc, err, d))
rc, out, err = w.wg("set", "wg0", "peer", key, "allowed-ips", "")
d = g.get("wg0")
L.check("empty allowed-ips replaces old prefixes", rc == 0 and w.peer_of(d, w.BOB_PUB)["ips"] == set(),
        "rc=%s err=%r state=%r" % (rc, err, d))
rc, out, err = w.wg("set", "missing-wg0", "listen-port", "23457")
L.check("kernel error reported after lookup", rc != 0 and bool(err.strip())
        and g.get("wg0").get("port") == 23456, "rc=%s err=%r" % (rc, err))
rc, out, err = w.wg("set", "wg0", "peer", key, "remove")
L.check("subsequent ACK and peer removal", rc == 0 and not g.get("wg0")["peers"],
        "rc=%s err=%r" % (rc, err))
sys.exit(L.finish("wg-set-transport-regression"))
