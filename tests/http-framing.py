#!/usr/bin/env python3
"""Verify exact HTTP helper output without contacting any network endpoint."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else "out/bash").resolve())
ENV = dict(os.environ)
if ENV.get("HTTP_LOAD_ENV"):
    ENV["BASH_ENV"] = ENV["HTTP_LOAD_ENV"]
if ENV.get("HTTP_ASAN_LIB"):
    ENV["LD_PRELOAD"] = ENV["HTTP_ASAN_LIB"]
    ENV["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1"
    ENV["UBSAN_OPTIONS"] = "halt_on_error=1"


def shell(script, *args):
    return subprocess.run([BINARY, "-c", "PATH=; " + script, "http-framing", *map(str, args)],
                          env=ENV, capture_output=True, timeout=5)


class FramingTests(unittest.TestCase):
    def test_exact_request_bytes_and_variable_agree(self):
        for body in ("", "abc", "line\r\nend\n", "café"):
            with self.subTest(body=body):
                expected = (b"POST /path?q=1 HTTP/1.1\r\nHost: example.test:8080\r\n"
                            b"User-Agent: bash-os/0.1\r\nAccept: */*\r\nX-Fixture: yes\r\n"
                            + f"Content-Length: {len(body.encode())}\r\n".encode()
                            + b"Connection: close\r\n\r\n" + body.encode())
                command = 'http request http://example.test:8080/path?q=1 -X POST -H "X-Fixture: yes" -d "$1"'
                printed = shell(command, body)
                bound = shell(command + ' -V REQUEST && printf "%s" "$REQUEST"', body)
                self.assertEqual(printed.returncode, 0, printed.stderr)
                self.assertEqual(bound.returncode, 0, bound.stderr)
                self.assertEqual(printed.stdout, expected)
                self.assertEqual(bound.stdout, expected)

    def test_url_query_fragment_and_ipv6_authority(self):
        for url, target, authority in (
            ("http://example.test?x=1#local", "/?x=1", "example.test"),
            ("https://example.test/path#local", "/path", "example.test"),
            ("https://[::1]:8443/", "/", "[::1]:8443"),
        ):
            with self.subTest(url=url):
                result = shell('http request "$1"', url)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith(f"GET {target} HTTP/1.1\r\nHost: {authority}\r\n".encode()))
        parsed = shell('http parse-url https://[::1]:8443/path')
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertEqual(parsed.stdout, b"scheme=https host=::1 port=8443 path=/path\n")

    def test_invalid_urls_are_rejected_without_output(self):
        for url in ("ftp://example.test/file", "http://example.test:abc/", "http://example.test:65536/",
                    "http://example.test:0/", "http://example.test:/", "http://user@example.test/",
                    "http://[not-ipv6]/", "http://::1/", "http://example.test/a b",
                    "http://example.test/\r\nInjected: yes", "http://example.test/" + "a" * 1024):
            for verb in ("parse-url", "request"):
                with self.subTest(url=url[:80], verb=verb):
                    result = shell('http "$1" "$2"', verb, url)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, b"")

    def test_method_and_header_injection_are_rejected(self):
        for method in ("", "GET /other", "POST\r\nInjected: yes", "GET\x01"):
            with self.subTest(method=method):
                result = shell('http request http://example.test/ -X "$1"', method)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
        for header in ("X: good\r\nInjected: yes", "X: good\nInjected: yes", "Bad Name: yes",
                       "No-colon", "X: control\x01", "Content-Length: 99", "host: wrong.test",
                       "Transfer-Encoding: chunked", "Connection: keep-alive"):
            with self.subTest(header=header):
                result = shell('http request http://example.test/ -H "$1"', header)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_output_failure_is_reported_and_does_not_poison_next_call(self):
        result = shell('for ((i=0;i<10;i++)); do '
                       'http request http://example.test/ >/dev/full; [[ $? == 1 ]] || exit 9; '
                       'done; http parse-url http://example.test/')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"scheme=http host=example.test port=80 path=/\n")

    def test_binding_errors_are_not_success(self):
        for command in ("parse-url http://example.test/", "request http://example.test/"):
            with self.subTest(command=command):
                result = shell('readonly result=original; http ' + command +
                               ' -V result; rc=$?; [[ $rc == 1 && $result == original ]]')
                self.assertEqual(result.returncode, 0, result.stderr)
                invalid = shell('http ' + command + ' -V 1invalid')
                self.assertEqual(invalid.returncode, 1, invalid.stderr)

    def test_malformed_status_does_not_replace_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target = Path(temporary) / "response", Path(temporary) / "body"
            for status in (b"HTTP/1.1 200oops", b"HTTP/1.1 +200 OK", b"HTTP/9.9 200 OK", b"HTTP/1.1 020 OK"):
                with self.subTest(status=status):
                    source.write_bytes(status + b"\r\n\r\nreplacement")
                    target.write_bytes(b"original")
                    result = shell('http response-body "$1" -o "$2"', source, target)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(target.read_bytes(), b"original")

    def test_binary_response_and_status_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target = Path(temporary) / "response", Path(temporary) / "body"
            source.write_bytes(b"HTTP/1.1 200 OK\r\n\r\na\x00b")
            result = shell('http response-body "$1" -o "$2" -S status && [[ $status == 200 ]]', source, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), b"a\x00b")
            readonly = shell('readonly status=original; http response-body "$1" -o "$2" -S status; '
                             'rc=$?; [[ $rc == 1 && $status == original ]]', source, target)
            self.assertEqual(readonly.returncode, 0, readonly.stderr)


if __name__ == "__main__":
    unittest.main()
