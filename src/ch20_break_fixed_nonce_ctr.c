// Challenge 20 - Break fixed-nonce CTR statistically
// https://cryptopals.com/sets/3/challenges/20
#include "ch20_break_fixed_nonce_ctr.h"
#include "ch01_hex_base64.h"
#include "ch03_single_byte_xor.h"
#include "ch18_aes_ctr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static uint8_t fixed_key[16];
static int key_initialized = 0;

// generate the random key once and reuse it for all calls
static void ensure_key(void)
{
    if (!key_initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++)
            fixed_key[i] = rand() % 256;
        key_initialized = 1;
    }
}

// read base64 lines from file, decode each into plains[i]
int load_plaintexts(const char *filename,
                    uint8_t plains[][CH20_MAX_LEN], int *plain_lens,
                    int max_count)
{
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char line[1024];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < max_count) {
        // strip newline
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        int n = base64_to_bytes(line, plains[count], CH20_MAX_LEN);
        if (n < 0) continue;
        plain_lens[count] = n;
        count++;
    }

    fclose(f);
    return count;
}

// encrypt every plaintext with the same key and the same nonce (= 0)
// this is the bug we're going to exploit
int encrypt_all_fixed_nonce(const uint8_t plains[][CH20_MAX_LEN],
                            const int *plain_lens, int count,
                            uint8_t ciphers[][CH20_MAX_LEN])
{
    ensure_key();

    for (int i = 0; i < count; i++) {
        int clen = aes_128_ctr(plains[i], plain_lens[i], fixed_key, 0,
                               ciphers[i], CH20_MAX_LEN);
        if (clen < 0) return -1;
    }
    return count;
}

// recover the keystream by attacking each column as single-byte XOR
int recover_keystream_stat(const uint8_t ciphers[][CH20_MAX_LEN],
                           const int *cipher_lens, int count,
                           uint8_t *keystream, int max_keystream)
{
    // find shortest cipher (only attack the common prefix)
    int min_len = cipher_lens[0];
    for (int i = 1; i < count; i++) {
        if (cipher_lens[i] < min_len) min_len = cipher_lens[i];
    }
    if (min_len > max_keystream) min_len = max_keystream;

    // each column was XORed with the same keystream byte across all rows
    // so building a "column buffer" turns it into single-byte XOR
    uint8_t column[CH20_MAX_TEXTS];
    uint8_t tmp[CH20_MAX_TEXTS];

    for (int col = 0; col < min_len; col++) {
        for (int row = 0; row < count; row++) {
            column[row] = ciphers[row][col];
        }

        xor_crack_result r = crack_single_byte_xor(column, count, tmp);
        keystream[col] = r.key;
    }

    return min_len;
}
