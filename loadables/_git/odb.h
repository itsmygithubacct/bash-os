/* SPDX-License-Identifier: MIT */
/* _git/odb.h — git object database: loose objects, hashing, deflate.
 *
 * The object store code shared by the git builtins. obj exposes it as
 * verbs; pack reads the same loose objects when resolving REF_DELTA bases;
 * the porcelain commands build on it. Every function here works on a repo
 * root, the directory holding .git/.
 *
 * These helpers report their own failures with builtin_error, in git's
 * wording, so a caller only has to choose an exit status.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_ODB_H
#define BASH_OS_GIT_ODB_H

#include <stddef.h>

/* Object types, in the order git's object header names them. */
enum bgit_type { BGIT_BLOB, BGIT_TREE, BGIT_COMMIT, BGIT_TAG, BGIT_UNKNOWN };

/* "blob" / "tree" / "commit" / "tag", or "unknown". */
const char *bgit_type_name (enum bgit_type type);

/* 1 if NAME is one of git's four object types. */
int bgit_type_valid_name (const char *name);

/* 1 if NAME is acceptable as a `hash --literally` type: non-empty, and no
   control characters, spaces or DEL, which the object header cannot hold. */
int bgit_type_printable (const char *name);

/* Walk parent directories from START looking for a .git/ directory. Returns
   the malloc'd repo root (the parent of .git/), or NULL. */
char *bgit_find_repo (const char *start);

/* 1 if S is non-empty and entirely hexadecimal. */
int bgit_all_hex (const char *s);

/* Format a 20-byte object id as 40 hex digits plus NUL. */
void bgit_sha_to_hex (const unsigned char *sha, char *out);

/* Resolve a full or abbreviated object id against the loose object store,
   mirroring git's unique-prefix rule (4 hex digits minimum). Writes 40 hex
   digits plus NUL into FULL. Returns 0, or -1 for unknown or ambiguous. */
int bgit_resolve_prefix (const char *repo, const char *sha, char full[41]);

/* Read <repo>/.git/objects/<aa>/<bbbb...> and return the inflated object,
   header included. SHA may be abbreviated. Caller frees *out. */
int bgit_read_loose (const char *repo, const char *sha,
                     unsigned char **out, size_t *out_len);

/* 1 if the loose object file for the full id SHA is readable. */
int bgit_loose_exists (const char *repo, const char sha[41]);

/* Parse the "<type> <size>\0" object header. Returns the offset of the
   payload, or -1 if the header is not one git would have written. */
long bgit_parse_header (const unsigned char *data, size_t len,
                        enum bgit_type *type, size_t *payload_size);

/* Hash through sha1dc. DIGEST always receives the canonical SHA-1; the
   return value is -1 when a collision attack was detected, so a caller can
   refuse to write the object. */
int bgit_sha1 (const unsigned char *data, size_t n, unsigned char digest[20]);

/* Deflate DATA into a malloc'd buffer. Caller frees *out. */
int bgit_deflate (const unsigned char *data, size_t n,
                  unsigned char **out, size_t *out_len);

/* Write deflated bytes to <repo>/.git/objects/<aa>/<bbbb...>, atomically and
   mode 0444 as git does. An object already present is left alone. */
int bgit_write_loose (const char *repo, const char *sha,
                      const unsigned char *deflated, size_t dlen);

/* Build "<type> <len>\0<content>", hash it, and with DO_WRITE store it.
   SHA_HEX receives the object id even when nothing is written. */
int bgit_hash_and_write (const char *type, const unsigned char *content,
                         size_t clen, int do_write, const char *repo,
                         char sha_hex[41]);

/* Read all of FD into a malloc'd buffer. Caller frees *out. */
int bgit_slurp_fd (int fd, unsigned char **out, size_t *out_len);

/* Read all of PATH into a malloc'd buffer. Caller frees *out. */
int bgit_slurp_file (const char *path, unsigned char **out, size_t *out_len);

#endif /* BASH_OS_GIT_ODB_H */
