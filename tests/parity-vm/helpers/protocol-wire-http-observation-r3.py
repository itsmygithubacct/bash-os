#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disposable-VM-only HTTP fixture and independent byte oracle.

The parent discovers the listen port via the owned child's fd inode and proc
TCP table. The tests must run through the parity VM harness, never on a host.
"""
import json
import os
import re
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
import uuid

LIMIT = 32768
DIAG = Path(os.environ.get("HOME", ".")) / "http-trace.json"


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def receive(sock, timeout=4.0, trace=None):
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except (OSError, socket.timeout) as exc:
            if trace is not None:
                trace['receive_error'] = type(exc).__name__ + ': ' + str(exc)
                trace['receive_errno'] = exc.errno
                trace['partial_reply_hex'] = bytes(data).hex()
            raise
        if not chunk:
            if trace is not None:
                trace['eof_monotonic'] = time.monotonic()
            return bytes(data)
        data.extend(chunk)
        ensure(len(data) <= LIMIT, "reply exceeds capture limit")


def exact(actual, expected):
    ensure(actual == expected, "reply bytes differ from the independently specified wire response")


def control():
    # Prove the byte comparator rejects both changed content and missing EOF.
    expected = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\na\x00z"
    trace = {'scenario': 'control', 'expected_hex': expected.hex()}
    left, right = socket.socketpair()
    def sender():
        try:
            for part in (expected[:9], expected[9:45], expected[45:]):
                right.sendall(part)
        finally:
            right.close()
    thread = threading.Thread(target=sender)
    thread.start()
    try:
        actual = receive(left, trace=trace)
    finally:
        left.close()
        thread.join(timeout=2)
    ensure(not thread.is_alive(), "control writer did not finish")
    trace['actual_hex'] = actual.hex()
    exact(actual, expected)
    try:
        changed = actual[:-1] + b"x"
        trace['changed_hex'] = changed.hex()
        exact(changed, expected)
    except AssertionError:
        pass
    else:
        raise AssertionError("negative byte control was accepted")
    left, right = socket.socketpair()
    try:
        right.sendall(b"partial")
        try:
            receive(left, .2, trace)
        except socket.timeout:
            trace['missing_eof_observation'] = 'socket.timeout'
        else:
            raise AssertionError("missing-EOF control was accepted")
    finally:
        left.close()
        right.close()
    class ResetAfterReply:
        def __init__(self): self.first = True
        def settimeout(self, value): pass
        def recv(self, size):
            if self.first:
                self.first = False
                return expected
            raise ConnectionResetError('synthetic reset control')
    reset_trace = {}
    try:
        receive(ResetAfterReply(), trace=reset_trace)
    except ConnectionResetError:
        ensure(bytes.fromhex(reset_trace.get('partial_reply_hex', '')) == expected,
               'reset control lost the complete response')
        ensure(reset_trace.get('receive_error', '').startswith('ConnectionResetError:'),
               'reset control lost the terminal error')
    else:
        raise AssertionError('reset control was accepted as clean EOF')
    trace['reset_control'] = reset_trace
    DIAG.write_text(json.dumps(trace, indent=2) + '\n')
    print("http-control=ok")


def port_for(pid, fd, trace):
    link = os.readlink(f"/proc/{pid}/fd/{fd}")
    trace['listen_fd'] = fd
    trace['listen_fd_link'] = link
    match = re.fullmatch(r"socket:\[(\d+)\]", link)
    ensure(match is not None, "listen descriptor is not a socket")
    inode = match.group(1)
    rows = Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]
    matches = []
    for row in rows:
        fields = row.split()
        if len(fields) > 9 and fields[9] == inode and fields[3] == "0A":
            address, port = fields[1].split(":")
            matches.append((address, int(port, 16), row))
    trace['listen_inode'] = inode
    trace['tcp_matches'] = [{'address_hex': a, 'port': p, 'raw_row': row}
                            for a, p, row in matches]
    ensure(len(matches) == 1 and matches[0][0] == "0100007F" and matches[0][1] > 0,
           "ephemeral descriptor is not a unique listening 127.0.0.1 socket")
    return matches[0][1]


def shell_script(scenario):
    probe = scenario == "lifecycle"
    reply = scenario in ("lifecycle", "reply-file", "reply-stdin")
    probe_shell = r'''
httpd accept "$LFD" -H CFD -m METHOD -p TARGET -q QUERY -B body -l LENGTH -c CTYPE -r REMOTE -t 0 2>probe0.err
p0=$?
none0=yes
for v in CFD METHOD TARGET QUERY LENGTH CTYPE REMOTE; do [[ -v $v ]] && none0=no; done
httpd accept "$LFD" -H CFD -m METHOD -p TARGET -q QUERY -B body -l LENGTH -c CTYPE -r REMOTE -t 1 2>probe1.err
p1=$?
none1=yes
for v in CFD METHOD TARGET QUERY LENGTH CTYPE REMOTE; do [[ -v $v ]] && none1=no; done
''' if probe else ""
    reply_shell = {
        "lifecycle": 'httpd reply "$CFD" < /dev/null',
        "reply-file": 'httpd reply "$CFD" -s 404 -t text/plain -f response.bin',
        "reply-stdin": 'httpd reply "$CFD" < response.bin',
    }.get(scenario, "")
    return r'''unset CFD METHOD TARGET QUERY LENGTH CTYPE REMOTE
httpd listen 0 -a 127.0.0.1 -H LFD 2>listen.err
lr=$?
if (( lr != 0 )); then printf 'START %s -\n' "$lr"; exit 50; fi
''' + probe_shell + r'''
printf 'START %s %s\n' "$lr" "$LFD"
httpd accept "$LFD" -H CFD -m METHOD -p TARGET -q QUERY -B body -l LENGTH -c CTYPE -r REMOTE 2>accept.err
ar=$?
bound=no
for v in CFD METHOD TARGET QUERY LENGTH CTYPE REMOTE; do [[ -v $v ]] && bound=yes; done
printf 'ACCEPT %s bound=%s\n' "$ar" "$bound"
''' + (r'''
printf 'VARS %s|%s|%s|%s|%s|%s\n' "${METHOD-}" "${TARGET-}" "${QUERY-}" "${LENGTH-}" "${CTYPE-}" "${REMOTE-}"
if [[ -f body && ! -s body ]]; then body_state=empty; else body_state=missing-or-nonempty; fi
printf 'BODY %s\n' "$body_state"
if (( ar == 0 )); then
''' + reply_shell + r'''
  rr=$?
  [[ -e /proc/$$/fd/$CFD ]] && fd_state=open || fd_state=closed
  printf 'REPLY %s fd=%s\n' "$rr" "$fd_state"
fi
''' if reply else "") + (r'''
printf 'PROBES %s %s %s %s\n' "$p0" "$none0" "$p1" "$none1"
''' if probe else "")


REQUESTS = {
    "lifecycle": b"GET /camera/status?view=wide HTTP/1.1\r\nHost: fixture\r\n\r\n",
    "reply-file": b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n",
    "reply-stdin": b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n",
    "bad-line": b"NOT-A-REQUEST\r\n\r\n",
    "large-head": b"GET / HTTP/1.1\r\nX: " + b"x" * (8192 - len(b"GET / HTTP/1.1\r\nX: ")),
    "overlarge-head": b"GET / HTTP/1.1\r\nX: " + b"x" * (9216 - len(b"GET / HTTP/1.1\r\nX: ")),
    "large-length": b"POST / HTTP/1.1\r\nContent-Length: 16777217\r\n\r\n",
    "bad-length": b"POST / HTTP/1.1\r\nContent-Length: xyz\r\n\r\n",
    "conflict-length": b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
    "bad-header": b"GET / HTTP/1.1\r\nHeader without colon\r\n\r\n",
    "short-head": b"GET / HTTP/1.1\r\nHost: fixture\r\n",
    "short-body": b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab",
    "deadline-head": b"GET / HTTP/1.1\r\nHost: fixture\r\n",
    "deadline-body": b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\na",
}


def expected(scenario):
    if scenario in ("lifecycle", "reply-file", "reply-stdin"):
        code, reason, ctype = (404, "Not Found", "text/plain") if scenario == "reply-file" else (200, "OK", "application/json")
        body = b"" if scenario == "lifecycle" else b"\x00A\xff\n.z\r\n"
    else:
        code = (431 if scenario in ("large-head", "overlarge-head") else 413 if scenario == "large-length" else
                408 if scenario.startswith("deadline-") else 400)
        reason = {400: "Bad Request", 408: "Request Timeout", 413: "Payload Too Large", 431: "Request Header Fields Too Large"}[code]
        ctype, body = "text/plain", b""
    header = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii")
    return header + body


def main(shell, scenario):
    ensure(scenario in REQUESTS, "unknown scenario")
    trace = {"scenario": scenario, "request_hex": REQUESTS[scenario].hex()[:LIMIT * 2]}
    proc = None
    collected = False
    try:
        proc = subprocess.Popen([shell, "--noprofile", "--norc", "-c", shell_script(scenario)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        ready, _, _ = select.select([proc.stdout], [], [], 4)
        ensure(bool(ready), "shell did not announce its listening descriptor")
        line = proc.stdout.readline(LIMIT)
        trace["start"] = line.decode("utf-8", "replace")
        trace["start_hex"] = line.hex()
        match = re.fullmatch(rb"START 0 (\d+)\n", line)
        ensure(match is not None, "httpd listen failed or produced malformed descriptor")
        port = port_for(proc.pid, int(match.group(1)), trace)
        trace["port_is_ephemeral_loopback"] = True
        start = time.monotonic()
        trace['start_monotonic'] = start
        trace['sends'] = []
        with socket.create_connection(("127.0.0.1", port), timeout=3) as peer:
            before_send = time.monotonic()
            peer.sendall(REQUESTS[scenario])
            trace['sends'].append({'started_monotonic': before_send,
                                   'finished_monotonic': time.monotonic(),
                                   'length': len(REQUESTS[scenario]),
                                   'bytes_hex': REQUESTS[scenario].hex()[:LIMIT * 2]})
            if scenario in ("short-head", "short-body"):
                peer.shutdown(socket.SHUT_WR)
            if scenario == "deadline-body":
                # A trickle halfway through must not restart the total deadline.
                time.sleep(5)
                before_send = time.monotonic()
                peer.sendall(b"b")
                trace['sends'].append({'started_monotonic': before_send,
                                       'finished_monotonic': time.monotonic(),
                                       'length': 1, 'bytes_hex': '62'})
            receive_error = None
            try:
                wire = receive(peer, 15 if scenario.startswith("deadline-") else 4, trace)
            except (OSError, socket.timeout) as exc:
                receive_error = exc
                wire = bytes.fromhex(trace.get('partial_reply_hex', ''))
        elapsed = time.monotonic() - start
        trace['reply_hex'] = wire.hex()
        trace['expected_reply_hex'] = expected(scenario).hex()
        trace['reply_exact'] = wire == expected(scenario)
        trace['peer_terminal'] = ({'kind': 'clean-eof'} if receive_error is None else
                                  {'kind': 'receive-error', 'type': type(receive_error).__name__,
                                   'message': str(receive_error), 'errno': receive_error.errno})
        out, err = proc.communicate(timeout=4)
        collected = True
        trace.update(reply_hex=wire.hex(), elapsed_seconds=round(elapsed, 3),
                     shell_stdout=out[:LIMIT].decode("utf-8", "replace"),
                     shell_stderr=err[:LIMIT].decode("utf-8", "replace"), shell_status=proc.returncode,
                     shell_stdout_hex=out[:LIMIT].hex(), shell_stderr_hex=err[:LIMIT].hex())
        for name in ("listen.err", "accept.err", "probe0.err", "probe1.err"):
            path = Path(name)
            if path.is_file():
                raw = path.read_bytes()[:LIMIT]
                trace[name] = raw.decode("utf-8", "replace")
                trace[name + "_hex"] = raw.hex()
        lines = out.decode("utf-8", "replace").splitlines()
        accept_line = next((line for line in lines if line.startswith('ACCEPT ')), None)
        accept_match = re.fullmatch(r'ACCEPT (\d+) bound=(yes|no)', accept_line or '')
        trace['accept_observation'] = {'raw_line': accept_line,
                                       'status': int(accept_match.group(1)) if accept_match else None,
                                       'bound': accept_match.group(2) if accept_match else None,
                                       'diagnostic': trace.get('accept.err')}
        exact(wire, expected(scenario))
        ensure(proc.returncode == 0, "shell returned nonzero")
        success = scenario in ("lifecycle", "reply-file", "reply-stdin")
        if success:
            ensure(lines and lines[0] == "ACCEPT 0 bound=yes", "accept did not bind request variables")
            values = "GET|/camera/status|view=wide|0||127.0.0.1" if scenario == "lifecycle" else "GET|/||0||127.0.0.1"
            ensure("VARS " + values in lines, "accepted variables differ from GET request")
            ensure("BODY empty" in lines, "GET body file was not truncated")
            ensure("REPLY 0 fd=closed" in lines, "reply failed or did not close client descriptor")
            if scenario == "lifecycle":
                ensure("PROBES 3 yes 3 yes" in lines, "empty listener probes bound variables or did not return 3")
        else:
            m = re.fullmatch(r"ACCEPT (\d+) bound=(yes|no)", lines[0] if lines else "")
            ensure(m is not None and int(m.group(1)) != 0, "malformed request was accepted")
            if scenario.startswith("deadline-"):
                ensure(m.group(2) == "no", "timeout bound one or more output variables")
                ensure("timed out" in trace.get("accept.err", ""), "timeout diagnostic missing")
                ensure(8 <= elapsed <= 14.5, "deadline was not the documented total 10-second budget")
            if scenario == "large-length":
                ensure(elapsed < 4, "oversized length was not rejected before waiting for body")
        ensure(receive_error is None, "client did not receive clean EOF: " + str(receive_error))
        print("http-" + scenario + "=ok")
    except Exception as exc:
        trace["error"] = f"{type(exc).__name__}: {exc}"
        print("http fixture failed: " + trace["error"], file=sys.stderr)
        raise SystemExit(1)
    finally:
        if proc is not None and not collected:
            if proc.poll() is None:
                proc.kill()
            try:
                out, err = proc.communicate(timeout=2)
                trace["remaining_stdout"] = out[:LIMIT].decode("utf-8", "replace")
                trace["remaining_stderr"] = err[:LIMIT].decode("utf-8", "replace")
                trace["remaining_stdout_hex"] = out[:LIMIT].hex()
                trace["remaining_stderr_hex"] = err[:LIMIT].hex()
                trace["shell_status_after_cleanup"] = proc.returncode
                for name in ("listen.err", "accept.err", "probe0.err", "probe1.err"):
                    path = Path(name)
                    if path.is_file():
                        raw = path.read_bytes()[:LIMIT]
                        trace[name] = raw.decode("utf-8", "replace")
                        trace[name + "_hex"] = raw.hex()
                lines = out[:LIMIT].decode("utf-8", "replace").splitlines()
                accept_line = next((line for line in lines if line.startswith('ACCEPT ')), None)
                accept_match = re.fullmatch(r'ACCEPT (\d+) bound=(yes|no)', accept_line or '')
                trace['accept_observation'] = {'raw_line': accept_line,
                    'status': int(accept_match.group(1)) if accept_match else None,
                    'bound': accept_match.group(2) if accept_match else None,
                    'diagnostic': trace.get('accept.err')}
            except subprocess.TimeoutExpired:
                trace["cleanup_error"] = "owned shell did not exit"
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
    if len(sys.argv) == 2 and sys.argv[1] == "control":
        control()
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        raise SystemExit("usage: helper control | helper SHELL SCENARIO")
