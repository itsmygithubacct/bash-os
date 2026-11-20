/* SPDX-License-Identifier: MIT */
/* SHA-256 files and GNU/BSD checksum-file verification, using bundled mbedTLS. */
#include <config.h>
#include "loadables.h"
#include "_mbedtls_sha256.h"

#define SUM_NAME "sha256sum"
#define SUM_TAG "SHA256"
#define SUM_HEX 64
#define SUM_CTX mbedtls_sha256_context
#define SUM_INIT mbedtls_sha256_init
#define SUM_STARTS(c) mbedtls_sha256_starts((c), 0)
#define SUM_UPDATE mbedtls_sha256_update
#define SUM_FINISH mbedtls_sha256_finish
#define SUM_FREE mbedtls_sha256_free
#include "sum-file.h"

int sha256sum_builtin(WORD_LIST *list) { return sum_main(list); }

char *sha256sum_doc[] = {
    "Print SHA-256 checksums or verify GNU/BSD checksum files with -c.",
    "-b/-t select the marker; --tag selects BSD output; -z ends records with NUL.",
    "Verification: --quiet, --status, --strict, --warn, --ignore-missing.", NULL
};
struct builtin sha256sum_struct = {
    "sha256sum", sha256sum_builtin, BUILTIN_ENABLED, sha256sum_doc,
    "sha256sum [-bctwz] [--tag] [FILE...]", 0
};
