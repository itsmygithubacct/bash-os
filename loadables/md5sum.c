/* SPDX-License-Identifier: MIT */
/* MD5 files and GNU/BSD checksum-file verification, using bundled mbedTLS. */
#include <config.h>
#include "loadables.h"
#include "_mbedtls_md5.h"

#define SUM_NAME "md5sum"
#define SUM_TAG "MD5"
#define SUM_HEX 32
#define SUM_CTX mbedtls_md5_context
#define SUM_INIT mbedtls_md5_init
#define SUM_STARTS mbedtls_md5_starts
#define SUM_UPDATE mbedtls_md5_update
#define SUM_FINISH mbedtls_md5_finish
#define SUM_FREE mbedtls_md5_free
#include "sum-file.h"

int md5sum_builtin(WORD_LIST *list) { return sum_main(list); }

char *md5sum_doc[] = {
    "Print MD5 checksums or verify GNU/BSD checksum files with -c.",
    "-b/-t select the marker; --tag selects BSD output; -z ends records with NUL.",
    "Verification: --quiet, --status, --strict, --warn, --ignore-missing.", NULL
};
struct builtin md5sum_struct = {
    "md5sum", md5sum_builtin, BUILTIN_ENABLED, md5sum_doc,
    "md5sum [-bctwz] [--tag] [FILE...]", 0
};
