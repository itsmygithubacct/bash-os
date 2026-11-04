/* SPDX-License-Identifier: MIT */
/* Bounded record parsing only. Encoding is an explicit trusted-schema input;
 * this header performs no KDF, account lookup, or authentication decision. */
#ifndef BASHOS_ARGON2_PHC_RECORD_H
#define BASHOS_ARGON2_PHC_RECORD_H
#include "argon2-phc-codec.h"

struct bashos_phc_record {
  uint32_t memory, iterations, lanes;
  size_t salt_length, hash_length;
  unsigned char salt[64], hash[128];
};

static inline int
bashos_phc_decimal (const char *text, uint32_t *value)
{
  uint32_t n = 0;
  if (!*text) return -1;
  for (; *text; text++) {
    unsigned char c = (unsigned char) *text;
    if (c < '0' || c > '9' || n > (UINT32_MAX - (c - '0')) / 10)
      return -1;
    n = n * 10 + (c - '0');
  }
  *value = n;
  return 0;
}

/* Same resource bounds as the existing project verifier. Unknown, duplicate,
 * missing or empty parameters and extra separators fail before any KDF. Every
 * failure clears the output; callers cannot reuse a previously parsed record. */
static inline int
bashos_phc_parse_record (const char *text, enum bashos_phc_encoding encoding,
                         struct bashos_phc_record *out)
{
  static const char prefix[] = "$argon2id$v=19$";
  struct bashos_phc_record parsed = {0};
  char copy[512] = {0};
  char *params, *salt, *hash, *next;
  unsigned seen = 0;
  size_t length;
  int rc = -1;

  if (!out) return -1;
  memset(out, 0, sizeof *out);
  if (!text || (encoding != BASHOS_PHC_STANDARD_BASE64 &&
                encoding != BASHOS_PHC_LEGACY_HEX)) goto done;
  length = strnlen(text, sizeof copy);
  if (length == sizeof copy || length < sizeof prefix ||
      memcmp(text, prefix, sizeof prefix - 1)) goto done;
  memcpy(copy, text, length + 1);
  params = copy + sizeof prefix - 1;
  salt = strchr(params, '$');
  if (!salt) goto done;
  *salt++ = 0;
  hash = strchr(salt, '$');
  if (!hash) goto done;
  *hash++ = 0;
  if (strchr(hash, '$')) goto done;
  do {
    uint32_t value;
    unsigned bit;
    next = strchr(params, ',');
    if (next) *next++ = 0;
    if (strlen(params) < 3 || params[1] != '=' ||
        bashos_phc_decimal(params + 2, &value)) goto done;
    switch (params[0]) {
      case 'm': bit = 1; parsed.memory = value; break;
      case 't': bit = 2; parsed.iterations = value; break;
      case 'p': bit = 4; parsed.lanes = value; break;
      default: goto done;
    }
    if (seen & bit) goto done;
    seen |= bit;
    params = next;
  } while (params);
  if (seen != 7 || parsed.memory < 1024 || parsed.memory > 262144 ||
      parsed.iterations < 1 || parsed.iterations > 10 ||
      parsed.lanes < 1 || parsed.lanes > 8) goto done;
  if (bashos_phc_decode_field(salt, encoding, parsed.salt, sizeof parsed.salt,
                              &parsed.salt_length) || parsed.salt_length < 8 ||
      bashos_phc_decode_field(hash, encoding, parsed.hash, sizeof parsed.hash,
                              &parsed.hash_length) || parsed.hash_length < 16)
    goto done;
  *out = parsed;
  rc = 0;
done:
  for (size_t i = 0; i < sizeof parsed; i++) ((volatile unsigned char *) &parsed)[i] = 0;
  for (size_t i = 0; i < sizeof copy; i++) ((volatile unsigned char *) copy)[i] = 0;
  return rc;
}
#endif
