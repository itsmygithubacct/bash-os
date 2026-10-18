#!/usr/bin/env python3
"""Check nc stream lifetimes using only task-owned loopback sockets."""
import contextlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = dict(os.environ)
if ENV.get("NC_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["NC_LOAD_ENV"]
if ENV.get("NC_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["NC_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"


@contextlib.contextmanager
def peer(handler, count=1):
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)

        def serve():
            try:
                for _ in range(count):
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        handler(connection)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1]
        finally:
            worker.join(6)
            assert not worker.is_alive(), "fixture server did not finish"
            assert not errors, errors


def shell(script, *args, **kwargs):
    result = subprocess.run([BINARY, "-c", "PATH=; " + script, "nc-stream", *map(str, args)],
                            env=ENV, capture_output=True, timeout=6, **kwargs)
    if b"runtime error:" in result.stderr or b"ERROR: AddressSanitizer" in result.stderr:
        raise AssertionError(result.stderr)
    return result


class StreamTests(unittest.TestCase):
    def test_hangup_drains_every_queued_byte(self):
        payload = bytes(range(256)) * 256
        received = bytearray()

        def receive(connection):
            while chunk := connection.recv(65536):
                received.extend(chunk)
            connection.sendall(b"ack")

        with peer(receive) as port:
            source, writer = socket.socketpair()
            with source, writer:
                writer.sendall(payload)
                writer.shutdown(socket.SHUT_WR)
                result = shell('nc connect 127.0.0.1 "$1"', port, stdin=source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"ack")
        self.assertEqual(bytes(received), payload)

    def test_peer_eof_finishes_with_stdin_still_open(self):
        with peer(lambda connection: connection.sendall(b"reply\n")) as port:
            process = subprocess.Popen(
                [BINARY, "-c", 'PATH=; nc connect 127.0.0.1 "$1"; '
                 'rc=$?; printf "continued=%s\\n" "$rc"', "nc-stream", str(port)],
                env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.wait(timeout=3)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(process.stdout.read(), b"reply\ncontinued=0\n")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)

    def test_idle_wait_is_bounded(self):
        release = threading.Event()
        with peer(lambda connection: release.wait(5)) as port:
            process = subprocess.Popen(
                [BINARY, "-c", 'PATH=; nc connect 127.0.0.1 "$1" -w 1; '
                 'rc=$?; printf "continued=%s\\n" "$rc"', "nc-stream", str(port)],
                env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.wait(timeout=3)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(process.stdout.read(), b"continued=1\n")
            finally:
                release.set()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)

    def test_stdin_read_error_is_not_success(self):
        def receive(connection):
            while connection.recv(4096):
                pass

        with tempfile.TemporaryDirectory() as temporary, peer(receive) as port:
            fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = shell('nc connect 127.0.0.1 "$1"', port, stdin=fd)
            finally:
                os.close(fd)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"read stdin", result.stderr)

    def test_reset_is_not_success(self):
        def reset(connection):
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

        with peer(reset) as port:
            result = shell('nc connect 127.0.0.1 "$1"', port, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_repeated_calls_preserve_descriptors_and_signal_trap(self):
        with peer(lambda connection: None, count=12) as port:
            result = shell('trap : PIPE; '
                           'before=(/proc/self/fd/*); saved=$(trap -p PIPE); '
                           'for ((i=0;i<12;i++)); do '
                           'nc connect 127.0.0.1 "$1" </dev/null || exit; done; '
                           'after=(/proc/self/fd/*); '
                           '[[ ${#before[@]} == ${#after[@]} && $(trap -p PIPE) == "$saved" ]]',
                           port, stdin=subprocess.DEVNULL)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_udp_keeps_the_reply_drain_window(self):
        errors = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(5)

            def reply():
                try:
                    data, address = server.recvfrom(4096)
                    server.sendto(b"reply:" + data, address)
                except Exception as exc:
                    errors.append(exc)

            worker = threading.Thread(target=reply, daemon=True)
            worker.start()
            result = shell('nc connect 127.0.0.1 "$1" -u -w 1',
                           server.getsockname()[1], input=b"query")
            worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"reply:query")

    def test_invalid_waits_fail_before_connecting_or_listening(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            for verb in (f"connect 127.0.0.1 {port}", "listen 0 -s 127.0.0.1", f"scan 127.0.0.1 {port}"):
                for value in ("no", "1x", "-1", "2147484", "99999999999999999999999"):
                    with self.subTest(verb=verb, value=value):
                        result = shell(f'nc {verb} -w "$1"', value, stdin=subprocess.DEVNULL)
                        self.assertEqual(result.returncode, 2, result.stderr)

    def test_scan_ports_are_complete_decimal_numbers(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            for value in (f"{reserved.getsockname()[1]}suffix", "-1", "65536", "99999999999999999999999"):
                with self.subTest(value=value):
                    result = shell('nc scan 127.0.0.1 "$1"', value, stdin=subprocess.DEVNULL)
                    self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
