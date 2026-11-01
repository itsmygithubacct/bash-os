#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only mock fail2ban control daemon.

Usage: mig-w6-f2b-mock.py SOCKET REPLYFILE REPORT -- PROGRAM [ARG...]

Listens on the private Unix SOCKET, runs PROGRAM in its own session, answers each
connection with the bytes of REPLYFILE after reading one request (up to 64 KiB or
a 0.3 s idle gap), and writes REPORT as JSON {"connections": N, "requests": [hex...],
"status": PROGRAM exit status} when PROGRAM has exited. The listener and the child
are always reaped before this process exits.
"""
import json, os, select, signal, socket, subprocess, sys, time


def main():
    sock_path, reply_path, report = sys.argv[1:4]
    program = sys.argv[5:]
    reply = open(reply_path, "rb").read()
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(8)
    child = subprocess.Popen(program, start_new_session=True)
    requests = []
    status = None
    deadline = time.monotonic() + 20
    try:
        while status is None and time.monotonic() < deadline:
            r, _, _ = select.select([srv], [], [], 0.05)
            if r:
                conn, _ = srv.accept()
                data = b""
                conn.setblocking(False)
                end = time.monotonic() + 0.3
                while time.monotonic() < end:
                    ready, _, _ = select.select([conn], [], [], 0.05)
                    if ready:
                        try:
                            chunk = conn.recv(65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        data += chunk
                        end = time.monotonic() + 0.1
                requests.append(data.hex())
                try:
                    conn.setblocking(True)
                    conn.sendall(reply)
                except OSError:
                    pass
                conn.close()
            status = child.poll()
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        srv.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    json.dump({"connections": len(requests), "requests": requests, "status": child.returncode}, open(report, "w"))


if __name__ == "__main__":
    main()
