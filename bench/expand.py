#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the expand workload with a different line count using loadables.py.

All other arguments, validation and timing behavior come from that harness.
"""
import argparse
import hashlib
import sys

import loadables


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--lines', type=int, required=True)
    args, rest = parser.parse_known_args()
    if args.lines < 0:
        parser.error('--lines must be nonnegative')
    original = loadables.fixtures

    def fixtures(root):
        metadata = original(root)
        data = b'alpha\tbeta\tgamma\n' * args.lines
        (root / 'tabs').write_bytes(data)
        metadata['tabs'] = {'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()}
        return metadata

    loadables.fixtures = fixtures
    sys.argv = [sys.argv[0], *rest, '--only', 'expand']
    loadables.main()


if __name__ == '__main__':
    main()
