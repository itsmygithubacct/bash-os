/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PAX_STREAM_H
#define BASHOS_PAX_STREAM_H
#include <stdio.h>
struct bashos_pax_read_options {
    int extract, verbose, tar_mode, to_stdout, preserve;
    unsigned strip;
    const char **members;
    size_t count;
};
int bashos_pax_read(FILE *, const struct bashos_pax_read_options *);
int bashos_pax_write_member(FILE *, const char *, int no_recurse);
#endif
