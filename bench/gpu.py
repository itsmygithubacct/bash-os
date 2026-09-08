#!/usr/bin/env python3
"""Measure presenter traffic. Timing includes the Python protocol peer."""
import importlib.util
from pathlib import Path
import sys
import time

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gpu_peer', root/'tests/gpu-smoke.py')
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
peer.binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else root/'out/bash').resolve())
width, height, frames = 640, 360, 30
print(f'{width}x{height}, {frames} updates; timing includes the Python peer')
print(f'{"case":24s} {"tty bytes":>12s} {"bytes/update":>13s} {"seconds":>9s}')
for transport, mode in [('inline','full'), ('shm','full'), ('inline','patch'), ('shm','scroll')]:
    terminal = peer.Terminal()
    change = {
        'full': 'if ((i%2)); then gpu clear ff0000; else gpu clear 0000ff; fi',
        'patch': 'gpu pixel "$((i+20))" 30 ff0000',
        'scroll': 'gpu scroll -2 0 111827; gpu line 637 170 639 "$((160+i))" 60a5fa',
    }[mode]
    script = f'''gpu start {width} {height} --tty "$GPU_TEST_TTY" --transport {transport}
gpu clear 111827
gpu present
before=${{ gpu info; }}
for ((i=0;i<{frames};i++)); do
{change}
gpu present
done
printf '%s\\n' "$before"
gpu info
gpu stop
'''
    start = time.monotonic()
    result = terminal.run(script, env={'KITTY_KILIX_RENDERING':'1'})
    elapsed = time.monotonic()-start
    first, last = (dict(part.split('=',1) for part in line.split()) for line in result.decode().splitlines()[:2])
    count = int(last['bytes'])-int(first['bytes'])
    print(f'{transport+" / "+mode:24s} {count:12,d} {count/frames:13,.1f} {elapsed:9.3f}')
