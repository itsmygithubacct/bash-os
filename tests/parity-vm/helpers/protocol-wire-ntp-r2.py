#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded RFC 5905 loopback fixtures; execution is restricted to the parity VM."""
import ctypes
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
import uuid

OBSERVER = "/opt/bashos-parity/harness/helpers/protocol-wire-ptrace-r2.py"
LEGACY = "/opt/bashos-parity/harness/helpers/system-seccomp.py"
DIAG = Path(os.environ.get("HOME", ".")) / "ntp-trace.json"
MAX = 32768
EPOCH = 2208988800
CLOCK_CALLS = ("clock_settime", "clock_adjtime", "adjtimex", "settimeofday")
CLOCK_PROBE = r'''import ctypes, errno, json
libc = ctypes.CDLL(None, use_errno=True)
sec = ctypes.CDLL('libseccomp.so.2')
sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
ts = (ctypes.c_long * 2)(1, 0)
tv = (ctypes.c_long * 2)(1, 0)
tx = ctypes.create_string_buffer(512)
ctypes.cast(tx, ctypes.POINTER(ctypes.c_uint))[0] = 1
calls = [('clock_settime', (0, ctypes.addressof(ts))),
         ('clock_adjtime', (0, ctypes.addressof(tx))),
         ('adjtimex', (ctypes.addressof(tx),)),
         ('settimeofday', (ctypes.addressof(tv), 0))]
results = []
for name, args in calls:
    number = sec.seccomp_syscall_resolve_name(name.encode())
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(x) for x in args))
    results.append({'name': name, 'number': number, 'args': args,
                    'result': result, 'errno': ctypes.get_errno()})
print(json.dumps({'calls': results}), flush=True)
raise SystemExit(0 if all(x['number'] >= 0 and x['result'] == -1 and x['errno'] == errno.EPERM for x in results) else 1)
'''


def check(condition, why):
    if not condition:
        raise AssertionError(why)


def timestamp(unix):
    value = unix + EPOCH
    whole = int(value)
    return struct.pack("!II", whole & 0xffffffff, int((value - whole) * (1 << 32)) & 0xffffffff)


def request_ok(req):
    return len(req) == 48 and (req[0] & 7) == 3 and ((req[0] >> 3) & 7) == 4 and req[40:48] != b"\0" * 8


def response(req, scenario, offset):
    p = bytearray(48)
    p[0], p[1], p[3] = 0x24, 2, 0xec
    p[12:16] = b"LOCL"
    p[24:32] = req[40:48]
    now = timestamp(time.time() + offset)
    p[32:40] = p[40:48] = now
    if scenario == "wrong-origin": p[24] ^= 1
    if scenario == "alarm": p[0] |= 0xc0
    if scenario == "kod": p[1], p[12:16] = 0, b"RATE"
    if scenario == "wrong-mode": p[0] = 0x23
    if scenario == "zero-transmit": p[40:48] = b"\0" * 8
    return bytes(p[:12] if scenario == "short" else p)


class Timeval(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("usec", ctypes.c_long)]


class Timex(ctypes.Structure):
    _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long),
                ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long), ("status", ctypes.c_int),
                ("constant", ctypes.c_long), ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
                ("time", Timeval), ("tick", ctypes.c_long), ("ppsfreq", ctypes.c_long),
                ("jitter", ctypes.c_long), ("shift", ctypes.c_int), ("stabil", ctypes.c_long),
                ("jitcnt", ctypes.c_long), ("calcnt", ctypes.c_long), ("errcnt", ctypes.c_long),
                ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int), ("pad", ctypes.c_int * 11)]


def clock_state():
    tx = Timex()
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.adjtimex(ctypes.byref(tx))  # modes=0 is a read-only query
    check(rc >= 0, "read-only adjtimex query failed")
    return {"offset": tx.offset, "status": tx.status,
            "realtime": time.time(), "monotonic": time.monotonic()}


def clock_unchanged(before, after):
    check(before["offset"] == after["offset"] and before["status"] == after["status"],
          "adjtimex offset or status changed")
    delta = (after["realtime"] - before["realtime"]) - (after["monotonic"] - before["monotonic"])
    check(abs(delta) < .25, "CLOCK_REALTIME changed relative to monotonic")


def filtered(command, log):
    return [sys.executable, OBSERVER, "--log", str(log), "--"] + command


def log_records(path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def clock_probe(trace):
    log = Path(os.environ['HOME']) / 'clock-control-trace.json'
    result = subprocess.run(filtered([sys.executable, '-c', CLOCK_PROBE], log), capture_output=True, timeout=10)
    observation = log_records(log)
    detail = {'status': result.returncode, 'stdout': result.stdout[:MAX].decode('utf8', 'replace'),
              'stderr': result.stderr[:MAX].decode('utf8', 'replace'), 'observation': observation}
    trace['clock_control'] = detail
    check(result.returncode == 0 and observation is not None and 'error' not in observation,
          'clock observer positive control failed')
    records = observation.get('records', [])
    check([r.get('syscall') for r in records] == list(CLOCK_CALLS) and
          all(r.get('return') == -1 for r in records),
          'clock observer did not record and block each probe')
    probe = json.loads(detail['stdout'])
    check([r.get('name') for r in probe.get('calls', [])] == list(CLOCK_CALLS) and
          all(r.get('errno') == 1 and r.get('result') == -1 for r in probe['calls']),
          'control child did not observe EPERM on all clock calls')


def legacy_notification_probe(trace):
    # Reproduce the r1 null-pointer control while retaining its child result,
    # diagnostics, notification records, and inherited filter state. A missing
    # notification is diagnostic only; it is never treated as proof of absence.
    log = Path(os.environ['HOME']) / 'clock-legacy-notify.jsonl'
    script = ("import ctypes,errno,json; lib=ctypes.CDLL(None,use_errno=True); "
              "ctypes.set_errno(0); r=lib.clock_settime(0,ctypes.c_void_p()); e=ctypes.get_errno(); "
              "print(json.dumps({'result':r,'errno':e}),flush=True); "
              "raise SystemExit(0 if r == -1 and e == errno.EPERM else 1)")
    rules = []
    for name in CLOCK_CALLS:
        rules += ['--notify', name, '--reply', name + '=EPERM']
    result = subprocess.run([sys.executable, LEGACY] + rules + ['--log', str(log), '--', sys.executable, '-c', script],
                            capture_output=True, timeout=8)
    raw = log.read_bytes()[:MAX] if log.exists() else b''
    status_lines = [line for line in Path('/proc/self/status').read_text().splitlines()
                    if line.startswith(('NoNewPrivs:', 'Seccomp:', 'Seccomp_filters:'))]
    trace['legacy_notification_probe'] = {'status': result.returncode,
                                          'stdout': result.stdout[:MAX].decode('utf8', 'replace'),
                                          'stderr': result.stderr[:MAX].decode('utf8', 'replace'),
                                          'records': [json.loads(line) for line in raw.splitlines()],
                                          'raw_log_hex': raw.hex(), 'parent_filter_status': status_lines}


def control():
    trace = {'scenario': 'control'}
    try:
        packet = bytearray(48)
        packet[0] = 0x23
        packet[40:48] = bytes.fromhex("e000000001020304")
        trace['control_request_hex'] = bytes(packet).hex()
        check(request_ok(packet), "positive request control failed")
        p = response(packet, "normal", 0)
        trace['control_response_hex'] = p.hex()
        check(len(p) == 48 and p[24:32] == packet[40:48] and (p[0] & 7) == 4, "positive reply control failed")
        bad = bytearray(packet); bad[0] = 0x24
        trace['control_bad_request_hex'] = bytes(bad).hex()
        check(not request_ok(bad), "wrong-mode negative request control passed")
        bad = response(packet, "wrong-origin", 0)
        trace['control_bad_origin_response_hex'] = bad.hex()
        check(bad[24:32] != packet[40:48], "wrong-origin negative response control passed")
        legacy_notification_probe(trace)
        clock_probe(trace)
        print("ntp-control=ok")
    except Exception as exc:
        trace['error'] = type(exc).__name__ + ': ' + str(exc)
        print('ntp control failed: ' + trace['error'], file=sys.stderr)
        raise SystemExit(1)
    finally:
        DIAG.write_text(json.dumps(trace, indent=2) + '\n')


class Responder:
    def __init__(self, addresses, offsets, scenario="normal"):
        self.sockets, self.threads, self.records, self.errors = [], [], [], []
        self.scenario = scenario
        port = 0
        for address, offset in zip(addresses, offsets):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((address, port))
            if port == 0: port = sock.getsockname()[1]
            sock.settimeout(4)
            self.sockets.append(sock)
            thread = threading.Thread(target=self.worker, args=(sock, address, offset), daemon=True)
            self.threads.append(thread)
        self.port = port
        for thread in self.threads: thread.start()

    def worker(self, sock, address, offset):
        try:
            req, peer = sock.recvfrom(4096)
            entry = {"address": address, "request_hex": req.hex()[:MAX], "offset": offset}
            self.records.append(entry)
            if not request_ok(req):
                self.errors.append("invalid request on " + address)
                return
            if self.scenario != "timeout":
                reply = response(req, self.scenario, offset)
                entry["response_hex"] = reply.hex()
                sock.sendto(reply, peer)
        except Exception as exc:
            self.errors.append(type(exc).__name__ + ": " + str(exc))

    def finish(self):
        for thread in self.threads: thread.join(5)
        for sock in self.sockets: sock.close()
        check(not any(t.is_alive() for t in self.threads), "responder thread did not finish")
        check(not self.errors and len(self.records) == len(self.sockets), "responder did not receive exactly one valid request on each address: " + repr(self.errors))


def shell_call(shell, script, env, watch=False, trace=None):
    argv = [shell, "--noprofile", "--norc", "-c", script]
    log = Path(os.environ['HOME']) / 'clock-candidate-trace.json'
    if watch: argv = filtered(argv, log)
    start = time.monotonic()
    result = subprocess.run(argv, env=env, capture_output=True, timeout=8)
    elapsed = time.monotonic() - start
    observation = log_records(log) if watch else None
    if trace is not None and watch:
        trace['watched_process'] = {'status': result.returncode,
                                    'stdout': result.stdout[:MAX].decode('utf8', 'replace'),
                                    'stderr': result.stderr[:MAX].decode('utf8', 'replace'),
                                    'observation': observation}
    if watch:
        check(observation is not None and 'error' not in observation and observation.get('exec_seen'),
              'clock observer did not establish a guarded target')
        check(observation.get('exit_status') == result.returncode, 'clock observer exit-status mismatch')
    return {"status": result.returncode, "stdout": result.stdout[:MAX].decode("utf-8", "replace"),
            "stderr": result.stderr[:MAX].decode("utf-8", "replace"), "elapsed": elapsed,
            "mutations": observation.get('records', []) if watch else [], 'observation': observation}


def run_query(shell, scenario, trace):
    responder = Responder(["127.0.0.1"], [0], scenario)
    env = os.environ.copy()
    try:
        result = shell_call(shell, f"ntp query 127.0.0.1 -p {responder.port} -t 350", env)
    finally:
        responder.finish()
        trace["peer"] = responder.records
        trace["peer_errors"] = responder.errors
    trace["result"] = result
    if scenario == "normal":
        m = re.fullmatch(r"offset=(-?\d+\.\d{9}) delay=(-?\d+\.\d{9}) stratum=2 server=127\.0\.0\.1\n", result["stdout"])
        check(result["status"] == 0 and m is not None and abs(float(m.group(1))) < 1 and float(m.group(2)) >= 0, "normal response was not reported correctly")
    else:
        check(result["status"] != 0 and "offset=" not in result["stdout"] and bool(result["stderr"]), "invalid response or timeout was reported as success")
        if scenario == "kod":
            check("Kiss-o'-Death" in result["stderr"] and "RATE" in result["stderr"], "RATE kiss-of-death was not reported")
        if scenario == "timeout":
            check(.25 <= result["elapsed"] < 3 and "timeout" in result["stderr"].lower(), "no-response timeout was not bounded")


def run_serve(shell, scenario, trace):
    reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    count = 2 if scenario == "serve-max" else 1
    version = 3 if scenario == "serve-v3" else 4
    option = "--max 2" if count == 2 else "--once"
    cmd = f"ntp serve -S 127.0.0.1:{port} --stratum 3 --refid TEST --leap 2 {option}"
    proc = subprocess.Popen([shell, "--noprofile", "--norc", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    records = []
    try:
        # Wait for the owned child's socket rather than sending speculative
        # duplicate packets, which could accidentally satisfy --max 2.
        deadline = time.monotonic() + 4
        while True:
            check(proc.poll() is None, "server exited before binding")
            inodes = set(); fd_links = {}
            for fd in Path(f"/proc/{proc.pid}/fd").iterdir():
                try:
                    link = os.readlink(fd)
                    match = re.fullmatch(r"socket:\[(\d+)\]", link)
                    if match:
                        inodes.add(match.group(1)); fd_links[fd.name] = link
                except FileNotFoundError:
                    pass
            rows = Path(f"/proc/{proc.pid}/net/udp").read_text().splitlines()[1:]
            address = "0100007F:%04X" % port
            matched = [row for row in rows if len(row.split()) > 9 and
                       row.split()[1] == address and row.split()[9] in inodes]
            trace['bind_observation'] = {'fd_links': fd_links, 'local_hex': address,
                                         'port': port, 'matching_rows': matched}
            if matched:
                break
            check(time.monotonic() < deadline, "server did not bind its socket within bound")
            time.sleep(.02)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0)); peer.settimeout(3)
            for i in range(count):
                req = bytearray(48); req[0] = (version << 3) | 3
                req[40:48] = bytes.fromhex("e123456789abcdef") if i == 0 else bytes.fromhex("e123456789abcdee")
                peer.sendto(req, ("127.0.0.1", port))
                reply, source = peer.recvfrom(4096)
                records.append({"request_hex": bytes(req).hex(), "response_hex": reply.hex(), "source": source[0]})
                trace["peer"] = records
                check(len(reply) == 48 and source[0] == "127.0.0.1", "malformed response source or size")
                check((reply[0] & 7) == 4 and ((reply[0] >> 3) & 7) == version, "server must use mode 4 and echo client version")
                check(reply[0] >> 6 == 2 and reply[1] == 3 and reply[12:16] == b"TEST", "server leap/stratum/refid mismatch")
                check(reply[24:32] == req[40:48], "server originate timestamp mismatch")
                check(reply[32:40] != b"\0" * 8 and reply[40:48] != b"\0" * 8 and reply[32:40] <= reply[40:48], "server timestamps invalid")
        out, err = proc.communicate(timeout=3)
        trace["server"] = {"status": proc.returncode, "stdout": out[:MAX].decode("utf-8", "replace"), "stderr": err[:MAX].decode("utf-8", "replace")}
        check(proc.returncode == 0, "bounded server did not exit successfully")
    finally:
        if proc.poll() is None:
            proc.kill(); out, err = proc.communicate(timeout=2)
            trace["server_cleanup"] = {"status": proc.returncode, "stdout": out[:MAX].decode("utf-8", "replace"), "stderr": err[:MAX].decode("utf-8", "replace")}


def run_sync(shell, scenario, trace):
    clock_probe(trace)
    offsets = {"sync-odd": [-4, 2, 8], "sync-even": [-4, 2, 8, 10],
               "sync-panic-positive": [1200], "sync-panic-negative": [-1200],
               "sync-allow": [1200], "sync-limit": [4]}[scenario]
    addresses = ["127.0.0." + str(i + 2) for i in range(len(offsets))]
    responder = Responder(addresses, offsets)
    env = os.environ.copy(); env["BASHNTP_SERVER_PORT"] = str(responder.port)
    args = " ".join("-s " + a for a in addresses)
    args += " -P 1 -t 1000 " + ("-l 1" if scenario == "sync-limit" else "-n")
    if scenario == "sync-allow": args += " --allow-big-jump"
    before = clock_state()
    try:
        result = shell_call(shell, "ntp sync " + args, env, watch=True, trace=trace)
    finally:
        responder.finish(); trace["peer"] = responder.records; trace["peer_errors"] = responder.errors
    after = clock_state(); trace.update(before=before, after=after, result=result)
    clock_unchanged(before, after)
    check(not result["mutations"], "sync attempted a clock mutation")
    if scenario.startswith("sync-panic-"):
        check(result["status"] != 0 and "panic threshold" in result["stderr"] and "allow-big-jump" in result["stderr"], "panic threshold not enforced")
    elif scenario == "sync-limit":
        check(result["status"] != 0 and "exceeds limit" in result["stderr"] and "not applying" in result["stderr"], "limit did not refuse offset")
    else:
        m = re.fullmatch(r"offset=(-?\d+\.\d{9}) servers=(\d+)/(\d+) applied=no\n", result["stdout"])
        expected = 2 if scenario == "sync-odd" else 5 if scenario == "sync-even" else 1200
        check(result["status"] == 0 and m is not None and int(m.group(2)) == len(offsets) and int(m.group(3)) == len(offsets) and abs(float(m.group(1)) - expected) < .5,
              "median or dry-run result mismatch")


def run_daemon(shell, scenario, trace):
    clock_probe(trace)
    discipline = scenario.removeprefix("run-")
    responder = Responder(["127.0.0.1"], [.05])
    env = os.environ.copy(); env["BASHNTP_SERVER_PORT"] = str(responder.port)
    Path("ntp.conf").write_text("server 127.0.0.1\ninterval 17\nretry 3\ntimeout 1000\npolls 1\nlimit 9\nstep_threshold 0.25\ndiscipline " + discipline + "\n")
    before = clock_state()
    try:
        result = shell_call(shell, "ntp run -c ntp.conf -d state --once --dry-run-discipline", env, watch=True, trace=trace)
    finally:
        responder.finish(); trace["peer"] = responder.records; trace["peer_errors"] = responder.errors
    after = clock_state(); trace.update(before=before, after=after, result=result)
    clock_unchanged(before, after)
    check(not result["mutations"], "dry-run discipline attempted a clock mutation")
    expected_cfg = ("interval=17\nretry=3\ntimeout=1000\npolls=1\nlimit=9.000000\nstep_threshold=0.250000\nservers=1\n"
                    "discipline=" + discipline + "\ndiscipline_loop=pll\nleapfile=\nserve=0\n")
    cfg = Path("state/cfg").read_text(); last = Path("state/last").read_text()
    trace.update(cfg=cfg[:MAX], last=last[:MAX])
    check(result["status"] == 0 and cfg == expected_cfg, "configuration snapshot or --once status mismatch")
    m = re.fullmatch(r"offset=(-?\d+\.\d{9})\nservers=1/1\nwhen=(\d+)\n", last)
    check(m is not None and abs(float(m.group(1)) - .05) < .5 and before["realtime"] - 2 <= int(m.group(2)) <= after["realtime"] + 2,
          "last successful poll snapshot mismatch")
    check("discipline dry-run mode=" + discipline in result["stdout"] and "live_clock_settime=no live_ntp_adjtime=no" in result["stdout"],
          "dry-run discipline action line missing")


def main(shell, scenario):
    trace = {"scenario": scenario}
    try:
        if scenario.startswith("query-"): run_query(shell, scenario[6:], trace)
        elif scenario.startswith("serve-"): run_serve(shell, scenario, trace)
        elif scenario.startswith("sync-"): run_sync(shell, scenario, trace)
        elif scenario.startswith("run-"): run_daemon(shell, scenario, trace)
        else: raise ValueError("unknown scenario")
        print("ntp-" + scenario + "=ok")
    except Exception as exc:
        trace["error"] = type(exc).__name__ + ": " + str(exc)
        print("ntp fixture failed: " + trace["error"], file=sys.stderr)
        raise SystemExit(1)
    finally:
        DIAG.write_text(json.dumps(trace, indent=2) + "\n")


def require_guest():
    """Fail closed before helper behavior; the guest evaluator checks UUID equality."""
    try:
        marker = Path('/etc/bashos-parity-vm').read_text().strip()
        parsed = uuid.UUID(marker)
        if str(parsed) != marker.lower():
            raise ValueError('non-canonical VM marker')
        if Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('not a QEMU guest')
        if os.getuid() != 2000 or os.geteuid() != 2000:
            raise ValueError('unexpected guest uid')
        if Path.cwd() != Path('/tmp/parity-case') or os.environ.get('HOME') != '/tmp/parity-home':
            raise ValueError('unexpected guest scratch directory')
    except (OSError, ValueError) as exc:
        raise SystemExit('disposable-VM guard refused helper: ' + str(exc))


if __name__ == "__main__":
    require_guest()
    if len(sys.argv) == 2 and sys.argv[1] == "control": control()
    elif len(sys.argv) == 3: main(sys.argv[1], sys.argv[2])
    else: raise SystemExit("usage: helper control | helper SHELL SCENARIO")
