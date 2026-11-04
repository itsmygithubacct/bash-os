#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Guest-only local HTTP peer; compare curl after 100/103 interim heads."""
import importlib.util
import pathlib
import socket
import sys
import threading
import time

spec = importlib.util.spec_from_file_location('netlib', pathlib.Path(__file__).resolve().parent/'mig-w1-netlib.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


def exchange(which, interim):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    observed = []
    def peer():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(4)
                data = b''
                while b'\r\n\r\n' not in data and len(data) < 16384:
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                observed.append(data)
                conn.sendall(b'HTTP/1.1 ' + interim + b'\r\nX-Control: one\r\n\r\n'
                             b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nfin\n')
                time.sleep(1.5)
        except Exception as exc:
            observed.append(('peer-error:' + repr(exc)).encode())
        finally:
            listener.close()
    worker = threading.Thread(target=peer, daemon=True)
    worker.start()
    args = ['-sS', '--max-time', '1', 'http://127.0.0.1:%d/control' % port]
    result = L.cand('curl "$@"', *args, timeout=5) if which == 'candidate' else L.run(['/usr/bin/curl'] + args, timeout=5)
    worker.join(4)
    if worker.is_alive():
        raise RuntimeError('local peer did not exit')
    print('%s %s request=%r result=%r' % (which, interim.decode(), observed, result), file=sys.stderr, flush=True)
    L.check(which + ' peer received request', len(observed) == 1 and observed[0].startswith(b'GET /control HTTP/1.'), repr(observed))
    return result


if __name__ == '__main__':
    try:
        setup = L.run(['/usr/bin/ip', 'link', 'set', 'lo', 'up'])
        if not L.check('reference loopback setup', setup[0] == 0, repr(setup)):
            raise RuntimeError('loopback unavailable in disposable network namespace')
        for code in (b'100 Continue', b'103 Early Hints'):
            reference = exchange('reference', code)
            candidate = exchange('candidate', code)
            L.check(code.decode() + ' reference positive control', reference == (0, 'fin\n', ''), repr(reference))
            L.check(code.decode() + ' candidate equals reference', candidate == reference, repr(candidate))
    except Exception as exc:
        L.check('fixture completed', False, repr(exc))
    sys.exit(L.finish('interim'))
