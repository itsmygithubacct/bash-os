/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "../loadables/_tomlc17/tomlc17.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 4096) return 0;
    /* The parser's API requires a NUL after the length-delimited document. */
    char source[4097];
    memcpy(source, data, size);
    source[size] = 0;
    toml_result_t result = toml_parse(source, (int)size);
    toml_free(result);
    return 0;
}
