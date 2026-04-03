// Challenge 9 tests - PKCS#7 padding
extern "C" {
#include "ch09_pkcs7.h"
}
#include <gtest/gtest.h>

// cryptopals example: "YELLOW SUBMARINE" padded to 20 bytes
TEST(Ch09, PKCS7_Pad)
{
    const char *input = "YELLOW SUBMARINE"; // 16 bytes
    uint8_t output[32];

    int len = pkcs7_pad((const uint8_t *)input, 16, 20, output, sizeof(output));

    ASSERT_EQ(len, 20);
    EXPECT_EQ(output[16], 0x04); // last 4 bytes should be 0x04
    EXPECT_EQ(output[17], 0x04);
    EXPECT_EQ(output[18], 0x04);
    EXPECT_EQ(output[19], 0x04);
}

// if data is already a multiple, add a full block of padding
TEST(Ch09, PKCS7_Pad_FullBlock)
{
    const char *input = "1234567890123456"; // exactly 16 bytes
    uint8_t output[48];

    int len = pkcs7_pad((const uint8_t *)input, 16, 16, output, sizeof(output));

    ASSERT_EQ(len, 32); // 16 data + 16 padding
    EXPECT_EQ(output[16], 0x10); // 0x10 = 16
}

// unpad should remove padding correctly
TEST(Ch09, PKCS7_Unpad)
{
    uint8_t data[] = {'H', 'e', 'l', 'l', 'o', 3, 3, 3};
    int len = pkcs7_unpad(data, 8);
    EXPECT_EQ(len, 5); // "Hello" = 5 bytes
}

// invalid padding should return -1
TEST(Ch09, PKCS7_Unpad_Invalid)
{
    uint8_t data[] = {'H', 'e', 'l', 'l', 'o', 3, 3, 2}; // last byte doesn't match
    EXPECT_EQ(pkcs7_unpad(data, 8), -1);
}
