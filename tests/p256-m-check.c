/* Exercise the actual private arithmetic helpers, including their inlined use.
 * Build: cc -O2 tests/p256-m-check.c -o p256-m-check
 * Test-only reference multiplies may use widening instructions. */
#include "../loadables/_mbedtls/p256-m.c"
#include <inttypes.h>

static uint64_t state = UINT64_C(88172645463325252);
static uint32_t next_word(void)
{
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return (uint32_t) state;
}

static unsigned failures;
static void check_mul(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
    uint64_t want = (uint64_t) x * y + z + t;
    uint64_t got = u32_muladd64(x, y, z, t);
    if (want != got && failures++ < 4)
        printf("mul %08" PRIx32 " %08" PRIx32 " %08" PRIx32 " %08" PRIx32
               " want=%016" PRIx64 " got=%016" PRIx64 "\n", x, y, z, t, want, got);
}

static void check_limbs(uint32_t z[9], uint32_t x, uint32_t y[8], int alias)
{
    uint32_t want[9], got[9];
    memcpy(want, z, sizeof want); memcpy(got, z, sizeof got);
    const uint32_t *source = alias ? z : y;
    uint64_t carry = 0;
    for (unsigned i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t) x * source[i] + want[i] + carry;
        want[i] = (uint32_t) sum; carry = sum >> 32;
    }
    carry += want[8]; want[8] = (uint32_t) carry;
    uint32_t got_carry = u288_muladd(got, x, alias ? got : y);
    if ((got_carry != carry >> 32 || memcmp(got, want, sizeof got)) && failures++ < 4)
        printf("u288_muladd mismatch (alias=%d)\n", alias);
}

int main(void)
{
    const uint32_t edges[] = {0, 1, 0x7fff, 0xffff, 0x10000, 0x10001, 0x7fffffff, 0xffff0000, 0xffffffff};
    for (unsigned a = 0; a < sizeof edges / sizeof *edges; a++)
        for (unsigned b = 0; b < sizeof edges / sizeof *edges; b++)
            for (unsigned c = 0; c < sizeof edges / sizeof *edges; c++)
                for (unsigned d = 0; d < sizeof edges / sizeof *edges; d++)
                    check_mul(edges[a], edges[b], edges[c], edges[d]);
    for (unsigned i = 0; i < 1000000; i++) {
        uint32_t x = next_word(), y = next_word(), z = next_word(), t = next_word();
        check_mul(x, y, z, t);
    }
    for (unsigned i = 0; i < 100000; i++) {
        uint32_t z[9], y[8], x = next_word();
        for (unsigned j = 0; j < 9; j++) z[j] = next_word();
        for (unsigned j = 0; j < 8; j++) y[j] = next_word();
        check_limbs(z, x, y, 0); check_limbs(z, x, y, 1);
    }
    uint32_t z[9], y[8];
    memset(z, 0xff, sizeof z); memset(y, 0xff, sizeof y);
    check_limbs(z, UINT32_MAX, y, 0); check_limbs(z, UINT32_MAX, y, 1);
    printf("arithmetic: %u failures (6561 boundary + 1000000 random products, 200002 limb operations)\n", failures);
    /* ECDH is exposed by p256-m's C API, but not by the crypto builtin.
     * scalar 2 times G has the following independently known x coordinate. */
    const uint8_t g[64] = {
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
    };
    const uint8_t x2[32] = {
        0x7c,0xf2,0x7b,0x18,0x8d,0x03,0x4f,0x7e,0x8a,0x52,0x38,0x03,0x04,0xb5,0x1a,0xc3,
        0xc0,0x89,0x69,0xe2,0x77,0xf2,0x1b,0x35,0xa6,0x0b,0x48,0xfc,0x47,0x66,0x99,0x78
    };
    uint8_t sk[32] = {0}, secret[32] = {0}; sk[31] = 2;
    int rc = p256_ecdh_shared_secret(secret, sk, g);
    int bad_ecdh = rc != 0 || memcmp(secret, x2, sizeof secret);
    printf("ECDH: %s (rc=%d)\n", bad_ecdh ? "FAIL" : "PASS", rc);
    return failures != 0 || bad_ecdh;
}
