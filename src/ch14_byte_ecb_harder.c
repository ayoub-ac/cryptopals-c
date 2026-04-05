// Challenge 14 - Byte-at-a-time ECB decryption (Harder)
// https://cryptopals.com/sets/2/challenges/14
// Same as ch12 but the oracle prepends a random prefix before our input.
// We need to figure out the prefix length first, then use the same attack.
#include "ch14_byte_ecb_harder.h"
#include "ch01_hex_base64.h"
#include "ch07_aes_ecb.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char *unknown_b64 =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJpdmUg"
    "YnkK";

static uint8_t fixed_key[16];
static uint8_t prefix[64];
static size_t prefix_len = 0;
static int initialized = 0;

static void ensure_init(void)
{
    if (!initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++)
            fixed_key[i] = rand() % 256;
        // random prefix between 1 and 32 bytes
        prefix_len = (rand() % 32) + 1;
        for (size_t i = 0; i < prefix_len; i++)
            prefix[i] = rand() % 256;
        initialized = 1;
    }
}

int ecb_oracle_harder(const uint8_t *input, size_t input_len,
                      uint8_t *out, size_t out_size)
{
    ensure_init();

    uint8_t unknown[256];
    int unknown_len = base64_to_bytes(unknown_b64, unknown, sizeof(unknown));
    if (unknown_len < 0) return -1;

    // build: prefix + input + unknown
    uint8_t buf[4096];
    memcpy(buf, prefix, prefix_len);
    memcpy(buf + prefix_len, input, input_len);
    memcpy(buf + prefix_len + input_len, unknown, unknown_len);

    size_t total = prefix_len + input_len + unknown_len;

    return aes_128_ecb_encrypt(buf, total, fixed_key, out, out_size);
}

// find prefix length by looking for two identical blocks
int find_prefix_length(void)
{
    uint8_t out[4096];
    // send enough identical bytes that two full blocks will be the same
    // even with the prefix taking up part of a block
    uint8_t input[64];
    memset(input, 'A', sizeof(input));

    for (int pad = 0; pad < 16; pad++) {
        int len = ecb_oracle_harder(input, 32 + pad, out, sizeof(out));
        if (len < 0) return -1;

        // look for two consecutive identical blocks
        int nblocks = len / 16;
        for (int i = 0; i < nblocks - 1; i++) {
            if (memcmp(out + i * 16, out + (i + 1) * 16, 16) == 0) {
                // found them prefix_len = block boundary - pad
                return i * 16 - pad;
            }
        }
    }

    return -1;
}

int decrypt_ecb_harder(uint8_t *out, size_t out_size)
{
    int plen = find_prefix_length();
    if (plen < 0) return -1;

    // how many extra bytes to align prefix to a block boundary
    int align = (16 - (plen % 16)) % 16;
    // which block the actual data starts at
    int start_block = (plen + align) / 16;

    // figure out how long the secret is
    uint8_t tmp[4096];
    uint8_t pad[64];
    memset(pad, 'A', sizeof(pad));

    int base_len = ecb_oracle_harder(pad, align, tmp, sizeof(tmp));
    if (base_len < 0) return -1;

    int secret_len = 0;
    for (int i = 1; i <= 16; i++) {
        int len = ecb_oracle_harder(pad, align + i, tmp, sizeof(tmp));
        if (len > base_len) {
            secret_len = base_len - (plen + align) - i;
            break;
        }
    }

    if (secret_len <= 0 || (size_t)secret_len > out_size)
        return -1;

    // same byte-at-a-time attack as ch12, just offset by the prefix
    uint8_t input[4096];
    uint8_t cipher_ref[4096];
    uint8_t cipher_try[4096];

    for (int i = 0; i < secret_len; i++) {
        int block_num = start_block + (i / 16);
        int byte_in_block = i % 16;
        int pad_len = align + (15 - byte_in_block);

        // get reference: align + padding so target byte is at end of block
        memset(input, 'A', pad_len);
        ecb_oracle_harder(input, pad_len, cipher_ref, sizeof(cipher_ref));

        // try all 256 values
        uint8_t test[4096];
        memset(test, 'A', pad_len);
        memcpy(test + pad_len, out, i);

        int found = 0;
        for (int b = 0; b < 256; b++) {
            test[pad_len + i] = b;
            ecb_oracle_harder(test, pad_len + i + 1, cipher_try, sizeof(cipher_try));

            if (memcmp(cipher_ref + block_num * 16,
                       cipher_try + block_num * 16, 16) == 0) {
                out[i] = b;
                found = 1;
                break;
            }
        }

        if (!found) return -1;
    }

    return secret_len;
}
