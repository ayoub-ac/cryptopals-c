// Challenge 15 tests - PKCS#7 padding validation
extern "C" {
#include "ch15_pkcs7_validate.h"
}
#include <gtest/gtest.h>
#include <cstring>

// valid padding: "ICE ICE BABY\x04\x04\x04\x04"
TEST(Ch15, ValidPadding)
{
    uint8_t input[] = "ICE ICE BABY\x04\x04\x04\x04";
    uint8_t out[32];
    int len = pkcs7_validate_and_strip(input, 16, out, sizeof(out));
    ASSERT_EQ(len, 12);
    out[len] = '\0';
    EXPECT_STREQ((char *)out, "ICE ICE BABY");
}

// bad padding: last bytes don't match
TEST(Ch15, BadPadding_WrongValues)
{
    uint8_t input[] = "ICE ICE BABY\x05\x05\x05\x05";
    int len = pkcs7_validate_and_strip(input, 16, NULL, 0);
    EXPECT_EQ(len, -1);
}

// bad padding: not all bytes are the same
TEST(Ch15, BadPadding_Mixed)
{
    uint8_t input[] = "ICE ICE BABY\x01\x02\x03\x04";
    int len = pkcs7_validate_and_strip(input, 16, NULL, 0);
    EXPECT_EQ(len, -1);
}

// valid: single byte padding
TEST(Ch15, ValidSingleByte)
{
    uint8_t input[16];
    memset(input, 'A', 15);
    input[15] = 0x01;
    uint8_t out[16];
    int len = pkcs7_validate_and_strip(input, 16, out, sizeof(out));
    EXPECT_EQ(len, 15);
}

// valid: full block of padding
TEST(Ch15, ValidFullBlock)
{
    uint8_t input[16];
    memset(input, 0x10, 16);
    uint8_t out[16];
    int len = pkcs7_validate_and_strip(input, 16, out, sizeof(out));
    EXPECT_EQ(len, 0);
}

// bad: padding byte is zero
TEST(Ch15, BadPadding_Zero)
{
    uint8_t input[16];
    memset(input, 'A', 16);
    input[15] = 0x00;
    int len = pkcs7_validate_and_strip(input, 16, NULL, 0);
    EXPECT_EQ(len, -1);
}
