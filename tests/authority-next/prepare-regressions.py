#!/usr/bin/env python3
"""Extract two exact source functions for a narrow, injected regression fixture.

This prepares compiler inputs only. It never builds or executes a program.
The generated manifest binds both complete source inputs and function bodies.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def extract(text, name):
    starts = list(re.finditer(r'^(?:static )?int\n' + re.escape(name) + r'\s*\(', text, re.M))
    if len(starts) != 1:
        raise ValueError('missing or ambiguous source function: ' + name)
    start = starts[0].start()
    brace = text.index('{', starts[0].end())
    level, quote, comment, i = 0, None, None, brace
    while i < len(text):
        c = text[i]
        if comment == 'line':
            if c == '\n':
                comment = None
        elif comment == 'block':
            if text[i:i+2] == '*/':
                comment = None
                i += 1
        elif quote:
            if c == '\\':
                i += 1
            elif c == quote:
                quote = None
        elif text[i:i+2] in ('//', '/*'):
            comment = 'line' if text[i:i+2] == '//' else 'block'
            i += 1
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            level += 1
        elif c == '}':
            level -= 1
            if level == 0:
                return text[start:i+1] + '\n'
        i += 1
    raise ValueError('unterminated source function: ' + name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth-source', type=Path, required=True)
    parser.add_argument('--sshd-source', type=Path, required=True)
    parser.add_argument('--login-source', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    records = []
    sources = [
        (args.auth_source, 'ba_audit_read_text_cmd', 'auth-audit.inc'),
        (args.sshd_source, 'bsshd_auth_password_allowed', 'sshd-password.inc')]
    if args.login_source:
        sources.append((args.login_source, 'bl_exec_user', 'bl_exec_user.inc'))
    for source, name, output in sources:
        raw = source.read_bytes()
        body = extract(raw.decode(), name).encode()
        (args.output_dir / output).write_bytes(body)
        if name == 'bl_exec_user':
            # Adapt only the internal signature; keep the exact extracted body
            # and the existing fault/verdict assertions for both revisions.
            pinned = b'pinned_tty_fd' in body.split(b'{', 1)[0]
            (args.output_dir / 'bl_exec_user-abi.h').write_text(
                '#define BL_EXEC_USER_PINNED_TTY %d\n' % pinned)
        records.append({'source': source.name, 'source_sha256': hashlib.sha256(raw).hexdigest(),
                        'function': name, 'output': output, 'function_sha256': hashlib.sha256(body).hexdigest()})
        if name == 'bl_exec_user':
            records[-1]['signature_adapter_sha256'] = hashlib.sha256(
                (args.output_dir / 'bl_exec_user-abi.h').read_bytes()).hexdigest()
    (args.output_dir / 'source-manifest.json').write_text(json.dumps(records, indent=2) + '\n')
    print(json.dumps(records))


if __name__ == '__main__':
    main()
