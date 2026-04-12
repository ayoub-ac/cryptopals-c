// Challenge 17 tests - The CBC padding oracle
extern "C" {
#include "ch17_padding_oracle.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// known plaintext prefixes (first 6 bytes of each of the 10 strings)
static const char *known_prefixes[10] = {
    "000000", "000001", "000002", "000003", "000004",
    "000005", "000006", "000007", "000008", "000009"
};

static bool matches_any_known(const char *plain)
{
    for (int i = 0; i < 10; i++)
        if (strncmp(plain, known_prefixes[i], 6) == 0)
            return true;
    return false;
}

// fresh cipher should pass; at least one tamper of the last byte should fail
// (a single flip can leave padding valid by chance, so try a few)
TEST(Ch17, OracleBasic)
{
    uint8_t iv[16], cipher[256];
    int clen = padding_oracle_encrypt(iv, cipher, sizeof(cipher));
    ASSERT_GT(clen, 0);

    EXPECT_EQ(padding_oracle_check(iv, cipher, clen), 1);

    bool saw_invalid = false;
    for (int b = 0; b < 256; b++) {
        uint8_t tampered[256];
        memcpy(tampered, cipher, clen);
        tampered[clen - 1] ^= (uint8_t)b;
        if (padding_oracle_check(iv, tampered, clen) == 0) {
            saw_invalid = true;
            break;
        }
    }
    EXPECT_TRUE(saw_invalid) << "no XOR mask produced invalid padding";
}

// the full attack: decrypt without the key
TEST(Ch17, DecryptViaOracle)
{
    uint8_t iv[16], cipher[256], recovered[256];
    int clen = padding_oracle_encrypt(iv, cipher, sizeof(cipher));
    ASSERT_GT(clen, 0);

    int plen = padding_oracle_decrypt(iv, cipher, clen, recovered, sizeof(recovered));
    ASSERT_GT(plen, 0);
    recovered[plen] = '\0';

    printf("  recovered (%d bytes): %s\n", plen, recovered);
    EXPECT_TRUE(matches_any_known((const char *)recovered));
}

// run the attack a few times to catch edge cases from different random picks
TEST(Ch17, DecryptMultipleRuns)
{
    for (int run = 0; run < 5; run++) {
        uint8_t iv[16], cipher[256], recovered[256];
        int clen = padding_oracle_encrypt(iv, cipher, sizeof(cipher));
        ASSERT_GT(clen, 0);

        int plen = padding_oracle_decrypt(iv, cipher, clen, recovered, sizeof(recovered));
        ASSERT_GT(plen, 0) << "run " << run << " failed to decrypt";
        recovered[plen] = '\0';

        EXPECT_TRUE(matches_any_known((const char *)recovered))
            << "run " << run << " recovered: " << recovered;
    }
}
