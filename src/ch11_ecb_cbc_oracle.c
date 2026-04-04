/* Challenge 11 - ECB/CBC detection oracle
   https://cryptopals.com/sets/2/challenges/11

   An oracle encrypts data with a random key, randomly choosing
   ECB or CBC mode. We detect which one was used.

   The trick: feed repeated input bytes (like 48 'A's).
   ECB will produce repeated ciphertext blocks because identical
   plaintext blocks encrypt to identical ciphertext.
   CBC won't because of the chaining.
*/
#include "ch11_ecb_cbc_oracle.h"
#include "ch07_aes_ecb.h"
#include "ch10_aes_cbc.h"
#include "ch08_detect_ecb.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int rand_initialized = 0;

static void ensure_rand(void)
{
    if (!rand_initialized) {
        srand(time(NULL));
        rand_initialized = 1;
    }
}

static void random_bytes(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = rand() % 256;
}

// encrypt with random key, add 5-10 random bytes before and after,
// randomly choose ECB or CBC
int encryption_oracle(const uint8_t *input, size_t input_len,
                      uint8_t *out, size_t *out_len)
{
    ensure_rand();

    uint8_t key[16];
    random_bytes(key, 16);

    // add random padding before and after
    int prefix_len = 5 + (rand() % 6);
    int suffix_len = 5 + (rand() % 6);

    uint8_t padded[4096];
    random_bytes(padded, prefix_len);
    memcpy(padded + prefix_len, input, input_len);
    random_bytes(padded + prefix_len + input_len, suffix_len);

    size_t total = prefix_len + input_len + suffix_len;

    // randomly choose ECB or CBC
    int use_cbc = rand() % 2;

    if (use_cbc) {
        uint8_t iv[16];
        random_bytes(iv, 16);
        int len = aes_128_cbc_encrypt(padded, total, key, iv, out, 4096);
        if (len < 0) return -1;
        *out_len = len;
        return 1; // CBC
    } else {
        int len = aes_128_ecb_encrypt(padded, total, key, out, 4096);
        if (len < 0) return -1;
        *out_len = len;
        return 0; // ECB
    }
}

// detect by checking for repeated 16-byte blocks
int detect_ecb_or_cbc(const uint8_t *cipher, size_t len)
{
    int repeats = count_repeated_blocks(cipher, len, 16);
    return (repeats > 0) ? 0 : 1; // repeats = ECB, no repeats = probably CBC
}
