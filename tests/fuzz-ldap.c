/* SPDX-License-Identifier: MIT */
#define BASH_OS_LDAP_PARSER_ONLY 1
#include "../loadables/ldap.c"
void builtin_error(const char *format, ...) { (void)format; }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 4096) return 0;
    if (size && (data[0] & 1)) {
        char *filter = malloc(size);
        if (!filter) return 0;
        memcpy(filter, data + 1, size - 1);
        filter[size - 1] = 0;
        bl_buf encoded = {0};
        bl_compile_filter(filter, &encoded);
        bl_buf_free(&encoded);
        free(filter);
    } else {
        static FILE *sink;
        if (!sink) sink = fopen("/dev/null", "w");
        if (sink) bl_decode_ldap_message(data, size, sink, NULL, NULL, NULL);
    }
    return 0;
}
