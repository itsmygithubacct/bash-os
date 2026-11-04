/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "_bashauth_pwverify.h"
#include "_bashos_authcrypto_argon2id.h"

typedef struct {
  unsigned int m, t, p;
  unsigned char salt[64];
  unsigned char hash[128];
  size_t salt_len, hash_len;
  int hex_layout;
} bashos_phc_argon2id;

static void
bashos_pw_wipe (void *p, size_t n)
{
  volatile unsigned char *q = (volatile unsigned char *) p;
  while (q && n--)
    *q++ = 0;
}

static int
bashos_pw_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bashos_pw_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;

  for (const char *p = hex; *p; p++)
    {
      int v = bashos_pw_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

/* Existing BashOS hashes use hex; standard Argon2 PHC uses unpadded
   base64.  Prefer hex when both fields are valid hex, preserving existing
   stored hashes. */
static int
bashos_pw_unbase64 (const char *s, unsigned char *out, size_t cap)
{
  static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned int bits = 0, acc = 0;
  size_t n = 0, len = strlen (s);
  if (len % 4 == 1) return -1;
  for (; *s; s++)
    {
      const char *p = strchr (alphabet, (unsigned char) *s);
      if (!p) return -1;
      acc = (acc << 6) | (unsigned int) (p - alphabet);
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (n == cap) return -1;
          out[n++] = (unsigned char) (acc >> bits);
          acc &= (1u << bits) - 1;
        }
    }
  if (acc != 0) return -1; /* Non-canonical unused bits. */
  return (int) n;
}

static int
bashos_pw_parse_uint (const char *s, unsigned int *out)
{
  char *end = NULL;
  unsigned long v;

  if (!s || !*s)
    return -1;
  for (const char *p = s; *p; p++)
    if (*p < '0' || *p > '9') return -1;
  v = strtoul (s, &end, 10);
  if (!end || end == s || *end || v > 0xfffffffful)
    return -1;
  *out = (unsigned int) v;
  return 0;
}

static int
bashos_pw_parse_phc (const char *phc, bashos_phc_argon2id *out, int force_b64)
{
  if (!phc || strncmp (phc, "$argon2id$", 10) != 0)
    return -1;

  char *copy = strdup (phc);
  if (!copy)
    return -1;

  char *parts[5];
  char *cursor = copy + 1;
  for (int i = 0; i < 5; i++)
    {
      parts[i] = cursor;
      char *end = strchr (cursor, '$');
      if (i == 4)
        {
          if (end || !*cursor) goto fail;
        }
      else
        {
          if (!end || end == cursor) goto fail;
          *end = '\0';
          cursor = end + 1;
        }
    }

  if (strcmp (parts[0], "argon2id") != 0 ||
      strcmp (parts[1], "v=19") != 0)
    goto fail;

  memset (out, 0, sizeof *out);
  char *psave = NULL;
  unsigned seen = 0;
  if (parts[2][0] == ',' || parts[2][strlen (parts[2]) - 1] == ',' ||
      strstr (parts[2], ",,")) goto fail;
  for (char *kv = strtok_r (parts[2], ",", &psave); kv;
       kv = strtok_r (NULL, ",", &psave))
    {
      if (strncmp (kv, "m=", 2) == 0)
        {
          if ((seen & 1) || bashos_pw_parse_uint (kv + 2, &out->m) < 0) goto fail;
          seen |= 1;
        }
      else if (strncmp (kv, "t=", 2) == 0)
        {
          if ((seen & 2) || bashos_pw_parse_uint (kv + 2, &out->t) < 0) goto fail;
          seen |= 2;
        }
      else if (strncmp (kv, "p=", 2) == 0)
        {
          if ((seen & 4) || bashos_pw_parse_uint (kv + 2, &out->p) < 0) goto fail;
          seen |= 4;
        }
      else goto fail;
    }
  if (seen != 7) goto fail;

  int sl = bashos_pw_unhex (parts[3], out->salt, sizeof out->salt);
  int hl = bashos_pw_unhex (parts[4], out->hash, sizeof out->hash);
  out->hex_layout = sl >= 8 && hl >= 16 && !force_b64;
  if (!out->hex_layout)
    {
      sl = bashos_pw_unbase64 (parts[3], out->salt, sizeof out->salt);
      hl = bashos_pw_unbase64 (parts[4], out->hash, sizeof out->hash);
    }
  if (out->m < 1024 || out->m > 262144 ||
      out->t < 1 || out->t > 10 ||
      out->p < 1 || out->p > 8 ||
      sl < 8 || hl < 16)
    goto fail;
  out->salt_len = (size_t) sl;
  out->hash_len = (size_t) hl;
  free (copy);
  return 0;

fail:
  free (copy);
  return -1;
}

int
bashos_verify_phc_secret (const unsigned char *pw, size_t pw_len,
                          const char *phc)
{
  bashos_phc_argon2id parsed;
  unsigned char got[128];
  volatile unsigned char acc = 0;

  memset (&parsed, 0, sizeof parsed);
  memset (got, 0, sizeof got);

  if (bashos_pw_parse_phc (phc, &parsed, 0) < 0)
    return -1;

  if (bashos_auth_argon2id_raw (pw, pw_len, parsed.salt, parsed.salt_len,
                                parsed.t, parsed.m, parsed.p,
                                got, parsed.hash_len, 1, NULL) < 0)
    {
      bashos_pw_wipe (&parsed, sizeof parsed);
      bashos_pw_wipe (got, sizeof got);
      return -1;
    }

  for (size_t i = 0; i < parsed.hash_len; i++)
    acc |= (unsigned char) (got[i] ^ parsed.hash[i]);

  /* A standard Base64 field may consist entirely of hex characters.
     If the legacy interpretation did not match, try the standard one. */
  if (acc && parsed.hex_layout)
    {
      bashos_phc_argon2id alternate;
      memset (&alternate, 0, sizeof alternate);
      if (bashos_pw_parse_phc (phc, &alternate, 1) == 0 &&
          bashos_auth_argon2id_raw (pw, pw_len, alternate.salt,
                                   alternate.salt_len, alternate.t,
                                   alternate.m, alternate.p, got,
                                   alternate.hash_len, 1, NULL) == 0)
        {
          acc = 0;
          for (size_t i = 0; i < alternate.hash_len; i++)
            acc |= (unsigned char) (got[i] ^ alternate.hash[i]);
        }
      bashos_pw_wipe (&alternate, sizeof alternate);
    }
  bashos_pw_wipe (got, sizeof got);
  bashos_pw_wipe (&parsed, sizeof parsed);
  return acc == 0 ? 0 : 1;
}
