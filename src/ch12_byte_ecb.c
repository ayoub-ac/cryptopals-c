/* Challenge 12 - Byte-at-a-time ECB decryption (Simple)
   https://cryptopals.com/sets/2/challenges/12

   An oracle appends an unknown base64 string to our input
   and encrypts everything with AES-128-ECB using a fixed key.
   We don't know the key, but we can decrypt the unknown string
   byte by byte by controlling our input.
*/
#include "ch12_byte_ecb.h"
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
static int key_initialized = 0;

static void ensure_key(void)
{
    if (!key_initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++)
            fixed_key[i] = rand() % 256;
        key_initialized = 1;
    }
}

int ecb_oracle(const uint8_t *input, size_t input_len,
               uint8_t *out, size_t out_size)
{
    ensure_key();

    // decode the unknown string
    uint8_t unknown[256];
    int unknown_len = base64_to_bytes(unknown_b64, unknown, sizeof(unknown));
    if (unknown_len < 0) return -1;

    // build: input + unknown
    uint8_t buf[4096];
    memcpy(buf, input, input_len);
    memcpy(buf + input_len, unknown, unknown_len);

    size_t total = input_len + unknown_len;

    return aes_128_ecb_encrypt(buf, total, fixed_key, out, out_size);
}

int discover_block_size(void)
{
    uint8_t out[4096];

    // get base length with empty input
    int base_len = ecb_oracle(NULL, 0, out, sizeof(out));
    if (base_len < 0) return -1;

    // feed increasing bytes until output grows
    uint8_t input[64];
    memset(input, 'A', sizeof(input));

    for (int i = 1; i <= 64; i++) {
        int new_len = ecb_oracle(input, i, out, sizeof(out));
        if (new_len > base_len)
            return new_len - base_len;
    }

    return -1;
}

int decrypt_ecb_simple(uint8_t *out, size_t out_size)
{
    int block_size = discover_block_size();
    if (block_size < 0) return -1;

    // figure out how long the unknown string is
    uint8_t tmp[4096];
    int total_len = ecb_oracle(NULL, 0, tmp, sizeof(tmp));
    if (total_len < 0) return -1;

    // find exact length of unknown text
    uint8_t pad[64];
    memset(pad, 'A', sizeof(pad));
    int base = total_len;
    int unknown_len = 0;

    for (int i = 1; i <= block_size; i++) {
        int len = ecb_oracle(pad, i, tmp, sizeof(tmp));
        if (len > base) {
            unknown_len = base - i;
            break;
        }
    }

    if (unknown_len <= 0 || (size_t)unknown_len > out_size)
        return -1;

    // decrypt byte by byte
    uint8_t input[4096];
    uint8_t cipher_ref[4096];
    uint8_t cipher_try[4096];

    for (int i = 0; i < unknown_len; i++) {
        // which 16-byte block holds byte i, and where inside that block
        int block_num = i / block_size;
        int byte_in_block = i % block_size;
        // push unknown[i] to the last position of block_num using padding
        int pad_len = block_size - 1 - byte_in_block;

        // craft input: pad_len A's
        memset(input, 'A', pad_len);

        // get reference ciphertext
        ecb_oracle(input, pad_len, cipher_ref, sizeof(cipher_ref));

        // build the test block: pad + already known bytes + guess
        uint8_t test[4096];
        memset(test, 'A', pad_len);
        memcpy(test + pad_len, out, i);

        int found = 0;
        for (int b = 0; b < 256; b++) {
            test[pad_len + i] = b;
            ecb_oracle(test, pad_len + i + 1, cipher_try, sizeof(cipher_try));

            // compare the relevant block
            if (memcmp(cipher_ref + block_num * block_size,
                       cipher_try + block_num * block_size,
                       block_size) == 0) {
                out[i] = b;
                found = 1;
                break;
            }
        }

        if (!found) return -1;
    }

    return unknown_len;
}
