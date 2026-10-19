#!/usr/bin/env python3
"""Independent byte-exact crypto boundary, repeated-call and failure checks."""
import hashlib
import hmac
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESSIV

BINARY = str(Path(sys.argv.pop(1) if len(sys.argv) > 1 else 'out/bash').resolve())
ENV = {**os.environ, 'PATH': '', 'LC_ALL': 'C', 'BASHCRYPTO_NONCE_GUARD': '0'}
if ENV.get('CRYPTO_STATE_LOAD_ENV'):
    ENV.update(BASH_ENV=ENV['CRYPTO_STATE_LOAD_ENV'], LD_PRELOAD=ENV['CRYPTO_STATE_ASAN_LIB'],
               ASAN_OPTIONS='detect_leaks=0:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')

def shell(script, *args, data=None):
    p = subprocess.run([BINARY, '--noprofile', '--norc', '-c', script, '_', *map(str, args)],
                       input=data, capture_output=True, env=ENV, timeout=60)
    assert b'AddressSanitizer' not in p.stderr and b'runtime error:' not in p.stderr, p.stderr
    return p

class CryptoTests(unittest.TestCase):
    def test_hashes_and_hex_boundaries_repeated(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'
            for size in [0, 1, 55, 56, 63, 64, 65, 127, 128, 4095, 4096, 8192, 1048577]:
                data = (bytes(range(256))*((size+255)//256))[:size]
                file.write_bytes(data)
                for name in ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'blake2b']:
                    for mode in ['', '-x']:
                        with self.subTest(size=size, name=name, mode=mode):
                            p = shell(f'for ((i=0;i<3;i++)); do crypto {name} {mode} < "$1" || exit; done', file)
                            expected = hashlib.new(name, data).digest()
                            if mode: expected = expected.hex().encode()+b'\n'
                            self.assertEqual(p.returncode, 0, p.stderr)
                            self.assertEqual(p.stdout, expected*3)
            for length in [1, 2047, 2048, 2049, 65536]:
                p = shell('crypto shake256 -n "$1" -x', length, data=b'fixture')
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, hashlib.shake_256(b'fixture').hexdigest(length).encode()+b'\n')

    def test_hmac_key_allocation_boundaries(self):
        data = bytes(range(256))*257
        for name in ['md5', 'sha1', 'sha256', 'sha512']:
            for size in [0, 1, 63, 64, 65, 256, 257, 4096]:
                key = (bytes(range(256))*((size+255)//256))[:size]
                p = shell('crypto "$@"', 'hmac-'+name, '-k', key.hex(), '-x', data=data)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, hmac.new(key, data, name).hexdigest().encode()+b'\n')

    def test_regular_input_at_nonzero_offset(self):
        data = bytes(range(256))*31
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'; file.write_bytes(b'prefix\n'+data)
            key, nonce = bytes(32), bytes(12)
            p = shell('exec 3< "$1"; IFS= read -r prefix <&3; '
                      'crypto chacha20-poly1305 -e -k "$2" -n "$3" <&3', file, key.hex(), nonce.hex())
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, ChaCha20Poly1305(key).encrypt(nonce, data, None))

    def test_aead_reference_and_authenticated_failures(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'
            for name, impl, lengths in [('aes-gcm', AESGCM, [16,32]), ('chacha20-poly1305', ChaCha20Poly1305, [32])]:
                for keylen in lengths:
                    key, nonce, aad = bytes(range(keylen)), bytes(range(12)), b'header\x00fixture'
                    args = f'crypto {name} -k {key.hex()} -n {nonce.hex()} -A {aad.hex()}'
                    for size in [0, 1, 15, 16, 17, 4095, 4096, 4097, 1048577]:
                        data = (bytes(range(256))*((size+255)//256))[:size]
                        cipher = impl(key).encrypt(nonce, data, aad)
                        for flag, source, expected in [('-e', data, cipher), ('-d', cipher, data)]:
                            with self.subTest(name=name, size=size, flag=flag, keylen=keylen):
                                file.write_bytes(source)
                                p = shell(f'for ((i=0;i<3;i++)); do {args} {flag} < "$1" || exit; done', file)
                                self.assertEqual(p.returncode, 0, p.stderr)
                                self.assertEqual(p.stdout, expected*3)
                                if size == 1048577:
                                    piped = shell(args+' '+flag, data=source)
                                    self.assertEqual(piped.returncode, 0, piped.stderr)
                                    self.assertEqual(piped.stdout, expected)
                        corruptions = [cipher[:-1]+bytes([cipher[-1]^1]), cipher[:15]]
                        if size: corruptions.append(bytes([cipher[0]^1])+cipher[1:])
                        for corrupt in corruptions:
                            p = shell(args+' -d', data=corrupt)
                            self.assertEqual(p.returncode, 1, p.stderr)
                            self.assertEqual(p.stdout, b'')
                    cipher = impl(key).encrypt(nonce, b'fixture', aad)
                    for wrong in [args.replace(nonce.hex(), 'ff'*12), args.replace(aad.hex(), 'ff')]:
                        p = shell(wrong+' -d', data=cipher)
                        self.assertEqual(p.returncode, 1, p.stderr)
                        self.assertEqual(p.stdout, b'')

    def test_siv_reference_and_rejection(self):
        key, aad = bytes(range(32)), b'header'
        args = f'crypto aes-siv-cmac -k {key.hex()} -A {aad.hex()}'
        for size in [0, 15, 16, 17, 4097]:
            data = (bytes(range(256))*((size+255)//256))[:size]
            if data:
                cipher = AESSIV(key).encrypt(data, [aad])
            else:
                # cryptography 43 rejects empty SIV input. RFC 5297 S2V's
                # empty-message branch can be checked independently with CMAC.
                def cmac(message):
                    c = CMAC(algorithms.AES(key[:16])); c.update(message)
                    return int.from_bytes(c.finalize(), 'big')
                def dbl(value):
                    return ((value << 1) ^ (0x87 if value >> 127 else 0)) & ((1 << 128)-1)
                dvalue = dbl(cmac(bytes(16))) ^ cmac(aad)
                cipher = cmac((dbl(dvalue) ^ (1 << 127)).to_bytes(16, 'big')).to_bytes(16, 'big')
            p = shell(args+' -e', data=data)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, cipher)
            p = shell(args+' -d', data=cipher)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, data)
            p = shell(args+' -d', data=bytes([cipher[0]^1])+cipher[1:])
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertEqual(p.stdout, b'')
        for length in [0, 16, 31, 33, 64]:
            p = shell('crypto aes-siv-cmac -e -k "$1"', '00'*length, data=b'fixture')
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b'')

    def test_nonce_guard_failure_then_valid_decryption(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'; file.write_bytes(b'fixture')
            for name, impl, length in [('aes-gcm',AESGCM,16), ('chacha20-poly1305',ChaCha20Poly1305,32)]:
                key, nonce = bytes(length), bytes(12)
                cipher = impl(key).encrypt(nonce, b'fixture', None)
                cipherfile = Path(d)/'cipher'; cipherfile.write_bytes(cipher)
                args = f'crypto {name} -k {key.hex()} -n {nonce.hex()}'
                p = shell('export BASHCRYPTO_NONCE_GUARD=1; '+args+' -e < "$1" || exit; '+
                          args+' -e < "$1" && exit 81; '+args+' -d < "$2"', file, cipherfile)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, cipher+b'fixture')

    def test_key_iv_and_hex_validation(self):
        for name, good in [('aes-gcm',16), ('chacha20-poly1305',32)]:
            for flag, values in [('-k', ['', '0', 'gg', '00'*15, '00'*17, '00'*24, '00'*31, '00'*33]),
                                 ('-n', ['', '0', 'gg', '00'*11, '00'*13, '00'*16, '00'*17]),
                                 ('-A', ['0', 'zz', '00'*257])]:
                for value in values:
                    key = value if flag == '-k' else '00'*good
                    nonce = value if flag == '-n' else '00'*12
                    aad = value if flag == '-A' else ''
                    p = shell('crypto "$@"', name, '-e', '-k', key, '-n', nonce, '-A', aad, data=b'fixture')
                    self.assertNotEqual(p.returncode, 0, (name, flag, value))
                    self.assertEqual(p.stdout, b'')

    def test_failed_output_and_recovery(self):
        commands = ['crypto '+name+' '+mode for name in ['md5','sha1','sha256','sha384','sha512','blake2b'] for mode in ['', '-x']]
        commands += ['crypto hmac-'+name+' -k 000102 '+mode for name in ['md5','sha1','sha256','sha512'] for mode in ['', '-x']]
        commands += ['crypto x25519-pub -k '+('00'*32)+' '+mode for mode in ['', '-x']]
        commands += ['crypto x25519-shared -k '+('00'*32)+' -p 09'+('00'*31)+' '+mode for mode in ['', '-x']]
        commands += ['crypto shake256 -n 65536 -x', 'crypto random 32 -x']
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'; file.write_bytes(b'fixture')
            for name, impl, length in [('aes-gcm', AESGCM,16), ('chacha20-poly1305',ChaCha20Poly1305,32)]:
                args = f'crypto {name} -k {"00"*length} -n {"00"*12}'
                commands.append(args+' -e')
                cipherfile = Path(d)/(name+'.cipher')
                cipherfile.write_bytes(impl(bytes(length)).encrypt(bytes(12), b'fixture', None))
                commands.append(args+' -d < '+shlex.quote(str(cipherfile)))
            for command in commands:
                for redirection in ['>/dev/full', '>&-']:
                    with self.subTest(command=command, output=redirection):
                        p = shell(f'{command} < "$1" {redirection}; rc=$?; [[ $rc != 0 ]] || exit 80; '
                                  'crypto sha256 -x < "$1"', file)
                        self.assertEqual(p.returncode, 0, p.stderr)
                        self.assertEqual(p.stdout, hashlib.sha256(b'fixture').hexdigest().encode()+b'\n')

    def test_input_errors_and_file_descriptor_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/'input'; file.write_bytes(b'fixture')
            p = shell('before=(/proc/$$/fd/*); for ((i=0;i<100;i++)); do '
                      'crypto sha256 -x "$1" >/dev/null || exit; '
                      'crypto sha256 -x "$2" >/dev/null 2>/dev/null && exit 81; '
                      'crypto sha256 -x <&- >/dev/null 2>/dev/null && exit 82; '
                      'done; after=(/proc/$$/fd/*); [[ ${#before[@]} == ${#after[@]} ]]', file, d)
            self.assertEqual(p.returncode, 0, p.stderr)

if __name__ == '__main__': unittest.main()
