// Challenge 20 tests - Break fixed-nonce CTR statistically
extern "C" {
#include "ch20_break_fixed_nonce_ctr.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>
#include <cctype>

TEST(Ch20, RecoverKeystreamStatistical)
{
    uint8_t plains[CH20_MAX_TEXTS][CH20_MAX_LEN];
    int plain_lens[CH20_MAX_TEXTS];

    int count = load_plaintexts("../data/20.txt", plains, plain_lens,
                                CH20_MAX_TEXTS);
    ASSERT_GT(count, 0);
    printf("  loaded %d plaintexts\n", count);

    uint8_t ciphers[CH20_MAX_TEXTS][CH20_MAX_LEN];
    int n = encrypt_all_fixed_nonce(plains, plain_lens, count, ciphers);
    ASSERT_EQ(n, count);

    // cipher_lens are the same as plain_lens for CTR (stream cipher)
    uint8_t keystream[CH20_MAX_LEN];
    int ks_len = recover_keystream_stat(ciphers, plain_lens, count,
                                         keystream, sizeof(keystream));
    ASSERT_GT(ks_len, 0);
    printf("  recovered %d bytes of keystream\n", ks_len);

    // decrypt first 3 lines to eyeball the result
    for (int i = 0; i < 3; i++) {
        char out[CH20_MAX_LEN];
        for (int j = 0; j < ks_len; j++) {
            out[j] = ciphers[i][j] ^ keystream[j];
        }
        out[ks_len] = '\0';
        printf("  line %d: %s\n", i, out);
    }

    // first line should contain "'m rated" (skipping byte 0 which is hard to
    // recover statistically when it's a capital letter in a single column)
    char first[16];
    for (int j = 1; j < 9 && j < ks_len; j++) {
        char c = ciphers[0][j] ^ keystream[j];
        first[j - 1] = (char)tolower((unsigned char)c);
    }
    first[8] = '\0';
    EXPECT_STREQ(first, "'m rated");
}
