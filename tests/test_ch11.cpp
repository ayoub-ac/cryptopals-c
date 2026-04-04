// Challenge 11 tests - ECB/CBC detection oracle
extern "C" {
#include "ch11_ecb_cbc_oracle.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// feed 48 identical bytes so ECB produces repeated blocks
// run multiple times and check we detect correctly
TEST(Ch11, DetectOracle)
{
    // 48 bytes of 'A' = at least 2 identical 16-byte blocks in the middle
    uint8_t input[48];
    memset(input, 'A', sizeof(input));

    int correct = 0;
    int total = 20;

    for (int i = 0; i < total; i++) {
        uint8_t cipher[256];
        size_t cipher_len;

        int actual = encryption_oracle(input, sizeof(input), cipher, &cipher_len);
        int detected = detect_ecb_or_cbc(cipher, cipher_len);

        if (actual == detected)
            correct++;
    }

    printf("  detected correctly: %d/%d\n", correct, total);
    EXPECT_GE(correct, 18); // should get almost all right
}
