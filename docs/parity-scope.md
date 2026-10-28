# Bash and command parity scope

Complete parity means every in-scope behavior has evidence against an identified
reference under specified conditions. Passing the current suites is insufficient:
the historical corpus started with 600 deferred scenarios, and a command's existence or
help text does not prove its operation or option compatibility.

The [deferral review](parity-deferrals.md) preserves those original scenarios and
tracks verified migrations and the remaining obligations. Migration work is ongoing.

The scope covers the pinned Bash language, native builtins, all 286 default
injected commands and three optional commands, and the complete GNU Coreutils
command set installed in the reference guest. Other utilities use their actual
upstream implementation (for example curl, OpenSSH, util-linux or procps), rather
than being described as GNU programs. Project-specific commands use documented
contracts. Missing GNU commands and unavailable optional commands remain gaps.

## Reproducible inventories

The [0.1.3 inventory](data/parity-0.1.3-scope.json) records all 286 default and
three optional commands, 61 native Bash builtin names, 105 reference Coreutils
commands and all 600 original historical deferrals. Of those Coreutils commands, 32 have
no matching candidate builtin. These counts describe scope, not passes.

The batch 92 snapshot inventories 907 modern fixtures, of which 893 have selected
execution evidence on both builds. The historical topic index contains 252
migrated scenarios and 348 unresolved scenarios. Migrated topics and authored
fixtures without selected evidence add no passing cases. Three excluded current-
definition filesystem diagnostics recorded FAIL; their reasons and history are
disclosed in the [validation record](data/parity-0.1.3-validation.json).
The scope's package inventory describes the first 413-package image; validation
records both images and the first image's unavailable lock-content limitation.

Generate the source/fixture inventory after a build has unpacked the pinned Bash
source. This reads files and does not run a candidate:

```sh
python3 tests/parity-vm/scope.py --bash-source build/bash-5.3 \
  --output parity-scope.json
```

Add `--interfaces PATH/TO/interfaces.json` using the VM inventory evidence to
include observed Coreutils commands/options, package versions and candidate gaps.

The JSON lists every default/optional command, declared synopsis, parser option
strings where extractable, source hash, reference description, fixture purposes,
coverage exclusions and deferred topics. It also lists native Bash builtin
synopses, reserved-word help topics, `set`, `shopt`, invocation options, manual
domains and documented variables. Conditional source features are identified as
source inventory; runtime availability is a separate observation.

The VM `inventory` group supplies the runtime counterpart in
`results/inventory/interfaces.json`: actual builtin names, shell option states,
the installed GNU Coreutils command set, missing candidate commands, reference
help output, option tokens and package versions. Neither source parsing nor
help-token extraction claims a complete grammar or tested option interaction.
Each option and operand form still needs an explicit behavioral case and report.

## Required coverage

| Area | Scope and acceptance evidence |
|---|---|
| Bash syntax | Lexing, quoting, comments, aliases, reserved words, lists, pipelines, compound commands, functions and parser errors. |
| Expansion | Tilde, parameter, arithmetic, command/process substitution, splitting, globbing, brace expansion, arrays, namerefs, UTF-8 and empty/unset values. |
| Execution | Lookup, builtin/function/external precedence, environment assignments, subshells, process groups, job control, wait, signals, traps and exit status. |
| Redirection | All operators, descriptor duplication/closure/inheritance, here-documents/strings, noclobber, pipes and failure atomicity. |
| Builtins/options | Every native builtin, operand/option form, `set`/`shopt`, invocation mode, compatibility level, variables, startup files, interactive/readline/history/completion behavior. |
| CLI grammar | Every command/subcommand, short/long aliases, clustered options, argument forms, ordering, conflicts, `--`, abbreviations, invalid inputs and missing operands. |
| Bytes/status | Separate stdout/stderr, NUL and arbitrary bytes, statuses, signals, locale-dependent diagnostics, ordering and pipeline behavior. |
| Filesystems | Data, modes, owners, ACLs, xattrs, timestamps, hardlinks, symlinks, sparse files, unusual names, races, partial writes and rollback. |
| Terminals | Raw bytes, rendered cells/cursor, input modes, key maps, resize, job control, signals, EOF/hangup, save behavior, and restoration/cleanup. |
| Networking | Protocol bytes, framing, redirects, errors, timeouts, cancellation, partial I/O, DNS/UDP/TCP, credentials and file effects using synthetic isolated peers. |
| Kernel/devices | VM-only accounts, mounts, IPC, capabilities, block/device operations and lifecycle effects, with synthetic resources and explicit cleanup. |
| Independent data | Versioned normative corpora, external tool oracles, independent format decoders and fault injection; never candidate-generated expected results. |

GNU option ordering, abbreviations, `--`, stdin operands and common flags are
specified in the [GNU Coreutils manual](https://www.gnu.org/s/coreutils/manual/html_node/Common-options.html).
Bash domains are indexed in the [Bash 5.3 manual](https://www.gnu.org/s/bash/manual/html_node/index.html);
the pinned source, patches and regression tests identify the exact implementation
baseline. Online manuals can describe a newer utility version than the guest;
the recorded package versions and captured interfaces define an evaluation.

## Environment matrix and reporting

Qualification must distinguish static/dynamic builds, profiles and optional
modules, architectures and word sizes, locales (`C`, `C.UTF-8`, non-English),
timezones/DST, valid and malformed encodings, umask and permissions, synthetic
users/groups, filesystem types, kernel capabilities, terminal sizes and types,
pipe/file/PTY input, POSIX mode and Bash compatibility settings. One observed
combination is evidence for that combination only.

New language/terminal/network comparisons use an independently built Bash
5.3.15 shell. The legacy harness uses the guest's Debian Bash, recorded separately.
Reference utility versions and configuration are part of every run's provenance.
Custom command contracts, metadata checks, harness selfchecks and behavioral
parity totals must remain distinguishable. Corpus-level totals must include
executed assertions, failures, errors, exclusions and the precise denominator;
a single corpus summary is not one independent behavioral assertion.

Exact help/version branding is a project contract, not a claim to reproduce GNU
copyright or version text. Error diagnostics remain exact when the case requires
them; a case that only checks an error category must say so. PTY semantic checks
must state the operation and screen/file assertions they verify and preserve raw
output, rather than normalizing an incompatibility away.

Upstream Bash/Coreutils regression-corpus integration, complete per-option
mapping, environment combinations, fault-injection paths and broad kernel/device
coverage remain explicit work items until executed evidence resolves them.
All 600 historical deferrals remain visible. Related new cases can provide
partial evidence, but only a reviewed scenario-by-scenario resolution can remove
a deferral. See [the VM harness](parity-vm.md) for execution and evidence handling.
