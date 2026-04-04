// Challenge 12 tests - Byte-at-a-time ECB decryption
extern "C" {
#include "ch12_byte_ecb.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

TEST(Ch12, DiscoverBlockSize)
{
    int bs = discover_block_size();
    EXPECT_EQ(bs, 16);
}

TEST(Ch12, DecryptUnknown)
{
    uint8_t result[256];
    int len = decrypt_ecb_simple(result, sizeof(result));

    ASSERT_GT(len, 0);
    result[len] = '\0';

    printf("  decrypted (%d bytes):\n%s\n", len, result);

    // should start with "Rollin' in my 5.0"
    EXPECT_TRUE(strncmp((char *)result, "Rollin'", 7) == 0);
}
