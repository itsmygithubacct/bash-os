/* SPDX-License-Identifier: MIT */
/* Explicit encoding selection for a reviewed PHC migration. This byte codec
 * performs no KDF or authentication. Existing account readers are not switched
 * here: the legacy project hex alphabet overlaps standard PHC base64, so callers
 * must select a format from their trusted account schema, never guess or retry. */
#ifndef BASHOS_ARGON2_PHC_CODEC_H
#define BASHOS_ARGON2_PHC_CODEC_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum bashos_phc_encoding { BASHOS_PHC_STANDARD_BASE64, BASHOS_PHC_LEGACY_HEX };

static inline int
bashos_phc_digit (unsigned char c, enum bashos_phc_encoding format)
{
  if (format == BASHOS_PHC_LEGACY_HEX) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  } else if (format == BASHOS_PHC_STANDARD_BASE64) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
  }
  return -1;
}

/* Canonical unpadded standard base64, or explicit legacy hex. Bounded to the
 * project's 128-byte maximum digest. On failure no output is returned. */
static inline int
bashos_phc_decode_field (const char *text, enum bashos_phc_encoding format,
                         unsigned char *out, size_t cap, size_t *length)
{
  unsigned char scratch[128] = {0};
  uint32_t accumulator = 0;
  unsigned bits = 0, width;
  size_t used = 0, n;
  int rc = -1;
  if (length) *length = 0;
  if (!text || !out || !length ||
      (format != BASHOS_PHC_STANDARD_BASE64 && format != BASHOS_PHC_LEGACY_HEX))
    return -1;
  n = strnlen (text, 257);
  if (!n || n > 256 || (format == BASHOS_PHC_LEGACY_HEX ? n % 2 : n % 4 == 1))
    return -1;
  width = format == BASHOS_PHC_LEGACY_HEX ? 4 : 6;
  for (size_t i = 0; i < n; i++) {
    int digit = bashos_phc_digit ((unsigned char) text[i], format);
    if (digit < 0) goto done;
    accumulator = (accumulator << width) | (unsigned) digit;
    bits += width;
    if (bits >= 8) {
      bits -= 8;
      if (used == sizeof scratch || used == cap) goto done;
      scratch[used++] = (unsigned char) (accumulator >> bits);
    }
    accumulator &= bits ? (1U << bits) - 1 : 0;
  }
  if (accumulator) goto done; /* Reject nonzero unused tail bits. */
  memcpy (out, scratch, used);
  *length = used;
  rc = 0;
done:
  for (size_t i = 0; i < sizeof scratch; i++) ((volatile unsigned char *) scratch)[i] = 0;
  return rc;
}

static inline int
bashos_phc_encode_field (const unsigned char *bytes, size_t n,
                         enum bashos_phc_encoding format, char *out, size_t cap)
{
  static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static const char hex[] = "0123456789abcdef";
  size_t need, used = 0;
  if (!bytes || !out || !n || n > 128 ||
      (format != BASHOS_PHC_STANDARD_BASE64 && format != BASHOS_PHC_LEGACY_HEX))
    return -1;
  need = format == BASHOS_PHC_LEGACY_HEX ? 2 * n : (8 * n + 5) / 6;
  if (cap <= need) return -1;
  if (format == BASHOS_PHC_LEGACY_HEX) {
    for (size_t i = 0; i < n; i++) {
      out[used++] = hex[bytes[i] >> 4];
      out[used++] = hex[bytes[i] & 15];
    }
  } else {
    uint32_t accumulator = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < n; i++) {
      accumulator = (accumulator << 8) | bytes[i];
      bits += 8;
      while (bits >= 6) { bits -= 6; out[used++] = base64[(accumulator >> bits) & 63]; }
      accumulator &= bits ? (1U << bits) - 1 : 0;
    }
    if (bits) out[used++] = base64[accumulator << (6 - bits)];
  }
  out[used] = 0;
  return 0;
}
#endif
