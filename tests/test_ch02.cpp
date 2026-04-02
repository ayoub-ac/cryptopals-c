// Challenge 2 tests - Fixed XOR
extern "C" {
#include "ch01_hex_base64.h"
#include "ch02_fixed_xor.h"
}
#include <gtest/gtest.h>

// main test: XOR two hex buffers using data from cryptopals.com
TEST(Ch02, FixedXOR)
{
    const char *hex_a = "1c0111001f010100061a024b53535009181c";
    const char *hex_b = "686974207468652062756c6c277320657965";
    const char *expected = "746865206b696420646f6e277420706c6179";

    // decode hex to bytes
    uint8_t a[64], b[64], result[64];
    int len_a = hex_to_bytes(hex_a, a, sizeof(a));
    int len_b = hex_to_bytes(hex_b, b, sizeof(b));
    ASSERT_EQ(len_a, len_b); // both must be same length

    // XOR them
    int n = fixed_xor(a, b, result, len_a);
    ASSERT_GT(n, 0);

    // convert result back to hex and compare
    char output[256];
    bytes_to_hex(result, n, output, sizeof(output));
    EXPECT_STREQ(output, expected);
}

// verify XOR cancels itself: a ^ b ^ b = a
TEST(Ch02, XOR_CancelsSelf)
{
    uint8_t a[] = {0x48, 0x65, 0x6C};
    uint8_t b[] = {0xFF, 0x01, 0xAB};
    uint8_t xored[3], back[3];

    fixed_xor(a, b, xored, 3);   // a ^ b
    fixed_xor(xored, b, back, 3); // (a ^ b) ^ b should give back a

    EXPECT_EQ(back[0], a[0]);
    EXPECT_EQ(back[1], a[1]);
    EXPECT_EQ(back[2], a[2]);
}
