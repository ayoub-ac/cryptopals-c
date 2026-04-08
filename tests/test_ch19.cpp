// Challenge 19 tests - Break fixed-nonce CTR
extern "C" {
#include "ch19_fixed_nonce_ctr.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// recover the keystream and use it to decrypt the first few lines
TEST(Ch19, RecoverKeystream)
{
    uint8_t ciphers[40][128];
    int cipher_lens[40];

    int count = encrypt_fixed_nonce(ciphers, cipher_lens, 40);
    ASSERT_EQ(count, 40);

    uint8_t keystream[64];
    int ks_len = recover_keystream(ciphers, cipher_lens, count,
                                    keystream, sizeof(keystream));
    ASSERT_GT(ks_len, 0);

    // decrypt and print first 5 lines so we can eyeball the result
    printf("  recovered %d bytes of keystream\n", ks_len);
    for (int i = 0; i < 5; i++) {
        char plain[64];
        for (int j = 0; j < ks_len; j++) {
            plain[j] = ciphers[i][j] ^ keystream[j];
        }
        plain[ks_len] = '\0';
        printf("  line %d: %s\n", i, plain);
    }

    // first line should start with "i have met" (case may vary, scoring prefers lowercase)
    char first[64];
    for (int j = 0; j < ks_len && j < 10; j++) {
        first[j] = ciphers[0][j] ^ keystream[j];
        if (first[j] >= 'A' && first[j] <= 'Z') first[j] += 32;
    }
    first[10] = '\0';
    EXPECT_STREQ(first, "i have met");
}
