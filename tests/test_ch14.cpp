// Challenge 14 tests - Byte-at-a-time ECB decryption (Harder)
extern "C" {
#include "ch14_byte_ecb_harder.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// make sure we can find the prefix length
TEST(Ch14, FindPrefixLength)
{
    int plen = find_prefix_length();
    printf("  detected prefix length: %d\n", plen);
    ASSERT_GT(plen, 0);
    ASSERT_LE(plen, 32);
}

// the actual attack: decrypt the secret with the prefix in the way
TEST(Ch14, DecryptWithPrefix)
{
    uint8_t result[256];
    int len = decrypt_ecb_harder(result, sizeof(result));

    ASSERT_GT(len, 0);
    result[len] = '\0';

    printf("  decrypted (%d bytes):\n%s\n", len, result);
    EXPECT_TRUE(strncmp((char *)result, "Rollin'", 7) == 0);
}
