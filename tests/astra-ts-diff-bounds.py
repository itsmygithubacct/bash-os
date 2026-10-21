#!/usr/bin/env python3
"""Exercise the actual incremental scanner guards without large allocations.

Usage: astra-ts-diff-bounds.py SOURCE.c OUTPUT.c
Compile OUTPUT.c as C11, optionally with ASan/UBSan, and run it. The two
production while conditions are extracted verbatim; a uint64_t oracle
checks that their uint32_t chunk counters cannot pass their limits.
This checks arithmetic only; full parse equivalence has separate tests.
"""
import hashlib
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text()
start = source.index('    uint32_t n = (uint32_t) srclen;', source.index('\nbashts_sgr_range_budget ('))
end = source.index('            TSInputEdit e;', start)
guards = re.findall(r'while \(([^&;{}]+)&& memcmp', source[start:end])
assert len(guards) == 2, 'expected prefix and suffix chunk guards'
prefix, suffix = (g.strip() for g in guards)
code = r'''
#include <stdint.h>
#include <stdio.h>
static int prefix_ok(uint32_t pre, uint32_t max) { return PREFIX; }
static int suffix_ok(uint32_t pre, uint32_t suf, uint32_t max) { return SUFFIX; }
int main(void) {
    const uint32_t points[] = {0, 1, 4095, 4096, 4097, 8192,
        UINT32_MAX-8192, UINT32_MAX-4096, UINT32_MAX-4095,
        UINT32_MAX-1, UINT32_MAX};
    unsigned checks = 0, failures = 0;
    for (unsigned m = 0; m < sizeof points / sizeof *points; m++) {
        uint32_t max = points[m];
        for (unsigned p = 0; p < sizeof points / sizeof *points; p++) {
            uint32_t pre = points[p];
            if (pre > max) continue;
            uint64_t remaining = (uint64_t)max - pre;
            checks++;
            if (prefix_ok(pre, max) != (remaining >= 4096)) {
                if (failures++ < 4) fprintf(stderr, "FAIL prefix pre=%u max=%u\n", pre, max);
            }
            for (unsigned s = 0; s < sizeof points / sizeof *points; s++) {
                uint32_t suf = points[s];
                if (suf > remaining) continue;
                checks++;
                if (suffix_ok(pre, suf, max) != (remaining - suf >= 4096)) {
                    if (failures++ < 4) fprintf(stderr, "FAIL suffix pre=%u suf=%u max=%u\n", pre, suf, max);
                }
            }
        }
    }
    printf("%s %u production scanner guard checks, %u failures\n",
           failures ? "FAIL" : "PASS", checks, failures);
    return failures != 0;
}
'''.replace('PREFIX', prefix).replace('SUFFIX', suffix)
Path(sys.argv[2]).write_text(code)
print('source sha256:', hashlib.sha256(source.encode()).hexdigest())
print('production prefix guard:', prefix)
print('production suffix guard:', suffix)
