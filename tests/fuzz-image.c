/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stddef.h>
#define STBI_MAX_DIMENSIONS 512
#define STB_IMAGE_IMPLEMENTATION
#include "../loadables/_stb/stb_image.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;
    int x, y, channels;
    void *pixels = stbi_load_from_memory(data, (int)size, &x, &y, &channels, 4);
    stbi_image_free(pixels);
    return 0;
}
