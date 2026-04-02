// Challenge 1 tests - Hex to Base64
extern "C" {
#include "ch01_hex_base64.h"
}
#include <gtest/gtest.h>

// main test: convert hex to base64 using data from cryptopals.com
TEST(Ch01, HexToBase64)
{
    const char *input =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65"
        "206120706f69736f6e6f7573206d757368726f6f6d";
    const char *expected =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    char output[256]; // buffer for the result
    int ret = hex_to_base64(input, output, sizeof(output));
    ASSERT_GT(ret, 0); // should not return error
    EXPECT_STREQ(output, expected); // must match expected output
}

// check hex_to_bytes works with a known value ("Hel" in ASCII)
TEST(Ch01, HexToBytes_Basic)
{
    uint8_t buf[3];
    int n = hex_to_bytes("48656c", buf, sizeof(buf));
    ASSERT_EQ(n, 3);
    EXPECT_EQ(buf[0], 0x48); // 'H'
    EXPECT_EQ(buf[1], 0x65); // 'e'
    EXPECT_EQ(buf[2], 0x6C); // 'l'
}

// invalid hex characters should return error
TEST(Ch01, HexToBytes_InvalidChar)
{
    uint8_t buf[4];
    EXPECT_EQ(hex_to_bytes("zzzz", buf, sizeof(buf)), -1);
}

// odd length hex is not valid (always need pairs)
TEST(Ch01, HexToBytes_OddLength)
{
    uint8_t buf[4];
    EXPECT_EQ(hex_to_bytes("abc", buf, sizeof(buf)), -1);
}
