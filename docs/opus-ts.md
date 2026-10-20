# ts: capture precedence, handles and incremental edits

`ts` is the tree-sitter runtime builtin ([`loadables/ts.c`](../loadables/ts.c));
`hl` and nano's renderer use its highlight engine. This is unrelated to the
moreutils `ts` timestamp filter.

## Capture precedence

A highlight query often captures the same byte more than once. A JSON object
key matches both `(pair key: (_) @string.special.key)` and `(string) @string`.
An `escape_sequence` sits inside its string, and a bash `$x` sits inside its
double-quoted string. The engine used to paint captures in the order the query
cursor returned them, so the later, generic `@string` covered every JSON key.

Each byte now gets exactly one class, from a total order that does not depend
on match enumeration:

1. the narrower capture wins (a nested node beats its ancestor);
2. for equal spans, the pattern that comes first in the query wins. This is
   tree-sitter-highlight's rule, and the vendored `highlights.scm` files list
   specific patterns before generic ones;
3. within one pattern, the capture name declared first in the query wins;
4. if everything else is equal (only possible with partial overlap), the
   earlier start wins.

`ts highlight`, `hl` and `bashts_compute_sgr_map` (nano) all share one
resolver.

* default: the source with SGR escapes. A new escape is written only when the
  SGR code changes.
* `-S`: resolved spans `BS-BE SGR NAME`. Spans never overlap, come in
  ascending order, and each one is a maximal run of one winning capture. A
  string around an escape therefore shows up as three spans.
  **This changes `-S`:** it used to list every raw capture in match order.
* `-A`: every capture before precedence, in the same format, sorted by start,
  then outermost first, then query order. Exact duplicates are dropped.

Offsets are 0-based, half-open byte offsets. Columns in `node-range` and
`query` count bytes too. The JSON grammar's `escape_sequence` token for
`é` is only the two bytes `\u`, and the spans report that as it is.

Each language's compiled highlight query is now cached for the life of the
shell. A `TSQuery` is immutable once built, so nano no longer recompiles it on
every re-highlight.

## Handles

`ts parse-tree -L LANG -t VAR` stores the tree and a copy of its source.

* Handles are `T<slot>g<gen>[:i,j,...]`. Indices are absolute child indices,
  anonymous children included. `node-children -n` only filters which children
  are listed, so a handle names the same node no matter which listing produced
  it. (Before this change, `-n` emitted named-child indices that `node-type`
  then resolved as absolute indices, which picked the wrong node.)
* Numbers must be canonical decimal: no sign, no leading zero, no overflow,
  no trailing comma. Generation 0 is never issued.
* `free` releases the tree and its source. Old handles fail at once; when the
  slot is reused it gets the next generation. The pool has 32 slots, and
  running out is an error.
* New verbs: `node-sexp NODE`, `node-text NODE` (the exact source bytes), and
  `-t TREE` for `highlight` and `query`.

## Incremental edits

`ts edit TREE START OLD_END NEW_END -t VAR < NEW_SOURCE`:

* bytes `[START, OLD_END)` of the stored source were replaced by
  `[START, NEW_END)` of the new one. The verb checks the shared prefix and
  suffix, so a range that does not describe the change is refused with
  status 2 and the tree is left as it was;
* points for `ts_tree_edit` are computed from the old and new text;
* the edited copy of the old tree goes to the parser, so unchanged subtrees
  are reused;
* on success the slot's generation advances, every old root and node handle
  stops resolving, and `VAR` receives the new handle.

## Output and errors

Every printing verb flushes stdout and returns 1 with
`write error: <reason>` when the flush fails (for example to `/dev/full`).
The error state is cleared, so the next call in the same shell writes
normally. `cursor-walk -d` needs a non-negative integer, variable names must
be valid identifiers, and stray arguments to `node-*` are usage errors.

## Tests

* [`tests/opus-ts-highlight.py`](../tests/opus-ts-highlight.py) `[BINARY]`
  checks:
  * exact spans and renders, written by hand, for keys versus ordinary
    strings, nested objects, escapes inside keys, bash nesting, TOML,
    markdown_inline and Unicode byte offsets;
  * a Python precedence oracle over 40 generated JSON/bash fixtures and a
    32 KB fixture. It works from raw `ts query` captures, a code path separate
    from the resolver;
  * repeat renders, `hl` parity, descriptor counts, generations, freed and
    malformed handles, and pool exhaustion;
  * six incremental edits, each compared against a fresh parse, fresh spans
    and a fresh render;
  * refused edit ranges, invalid input, `/dev/full` on every printing verb,
    and nano self-tests.

  It fails on the pre-change binary at the first JSON key assertion.
* [`tests/opus-ts-sanitize.sh`](../tests/opus-ts-sanitize.sh) `[BINARY]` runs
  the same suite, plus the `parsing` group of `final-smoke.py`, against ts, hl,
  nano and the vendored runtime and grammars built with ASan, UBSan and LSan.
  It compiles, so run it through the build gate.

## Benchmark

[`bench/opus-ts.py`](../bench/opus-ts.py) times one shell process running P
passes in-process with an empty `PATH`. Before any timing, the expected output
of each workload is fixed:

* span and render outputs from the precedence oracle;
* parse output by its `(number)` count;
* query output by its capture-name counts.

Every sample's whole output must equal P copies of the expected output, or the
binary is marked `invalid-output` and gets no timing. There is one warm-up and
seven timed samples per workload.

The workloads are `ts-parse` and `ts-query` (the historical fixtures), plus
spans and render over the 39 KB object, a key-heavy 1,000-record JSON and a
1,000-function bash script, plus `ts-edit-highlight` (two incremental edits
with a re-highlight after each). All of these are self timings with no
external reference.

### Results (2026-10-19)

These are self timings on a shared 12-CPU host, pinned to CPU 11 by the bench
gate, with load between 2.5 and 3.8. Each figure is the median of seven
samples, each sample being five passes in one shell. The baseline is `9a73eaf`
and the new build is `935015c`; both are `--include ts,hl,nano`.

| workload | input bytes | resolved spans | baseline | new |
|---|---:|---:|---:|---:|
| ts-parse (array) | 39,109 | — | 91.3 | 101.7 |
| ts-query (object) | 39,133 | 10,005 captures | 215.9 | 201.2 |
| ts-spans-object | 39,133 | 10,003 | invalid output | 201.6 |
| ts-render-object | 39,133 | 10,003 | invalid output | 160.5 |
| ts-spans-keys | 103,341 | 18,000 | invalid output | 341.8 |
| ts-render-keys | 103,341 | 18,000 | invalid output | 267.1 |
| ts-spans-bash | 47,560 | 10,000 | invalid output | 192.8 |
| ts-render-bash | 47,560 | 10,000 | 184.2 | 159.2 |
| ts-edit-highlight | 103,341 + 2×29-byte edits | 36,006 | invalid output | 454.5 |
| `bench/loadables.py` nano selftest | — | — | 30.3 | 9.7 |

* **Invalid output:** the baseline output differs from the precedence oracle,
  for example JSON keys painted as plain strings or raw overlapping `-S`
  records. Those runs get no timing.
* **ts-render-bash:** the only highlight workload where the old engine
  happens to render correctly. It improves because the compiled query is
  cached and output is written in runs rather than with `putchar` per byte.
* **nano selftest:** improves because the query cache removes the per-render
  `ts_query_new`.
* **ts-parse and ts-query:** these paths differ only by one `fflush`. The
  unchanged `bench/loadables.py` run measured the opposite direction
  (`ts-query` 165.2 → 195.8, `ts-parse` 100.8 → 96.3). The differences are
  host noise, not a change.
* **Profiling:** `perf` is blocked here (`perf_event_paranoid=3`), so the
  stage split comes from these workloads. Over the same 39 KB object, parse
  plus query takes about 200 ms per 5 passes; resolving and writing spans
  costs about as much as the raw query listing, and rendering costs less.

Review qualifications: the historical nano selftest timing used five calls per
shell; only the first call compiles the cached query. It does not measure a
fresh-shell invocation or the combined corrected nano/ts implementation.
The incremental edit tests verify equality with a fresh parse, not subtree
reuse. Historical ts-parse timings disagreed across harnesses; no new speedup
is claimed and hardware performance-counter profiling was unavailable.

Handle destinations must be writable text scalars (including namerefs to such
scalars). Arrays, arithmetic/case-transforming attributes and dynamic variables
are rejected. If publishing an edited tree handle fails, the original source,
tree and generation remain usable. Failed parse-tree publication releases its
slot. These corrections are not included in the historical measurements above.
