# Sed's portable GNU regex backend

`loadables/common/sed-regex.h` is private to `loadables/sed.c`. Non-glibc
builds use this length-aware GNU engine for both addresses and substitutions.
Glibc builds retain their system engine. Defining `BASHSED_PORTABLE_REGEX`
selects the private engine on glibc as well, so the same production path can
be checked with native address and undefined-behavior sanitizers.

The subject length, search offset, capture offsets and pattern length are
explicit. NUL is data, including in character classes, captures and patterns
decoded from numeric escapes. Searches retain the preceding character's
context for word boundaries. BRE/ERE and case/multiline options use the same
syntax settings on both backends. The engine uses the active libc locale;
non-glibc locale databases and collation support are not identical to glibc's.

The public regex API and syntax variable are renamed and have internal
linkage. The engine does not override the shell's `regcomp`/`regexec`, and
no helper library or command companion is required. The existing build stages
common headers and includes their contents in its cache key.

The header is generated from the regex files in the GNU sed 4.9 release:

- Source: <https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz>
- Archive SHA-256: `6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181`
- Files: `lib/regex.h`, `lib/regex_internal.h`, `lib/regex_internal.c`,
  `lib/regcomp.c`, `lib/regexec.c`.
- Licence: LGPL-2.1-or-later. Upstream copyright notices remain in the header;
  see [the licence text](sol-sed-regex-LGPL-2.1.txt).

Regenerate with `python3 tests/sol-sed-vendor-regex.py sed-4.9.tar.xz`.
The generator verifies the archive hash, makes the API private, supplies
compiler compatibility definitions, and replaces the one-use dynamic capture
array with a checked allocation while retaining its failure and cleanup paths.
It does not change the regex matching algorithms. GCC or Clang overflow and
attribute builtins are required, as with the supported Bash-OS toolchains.
