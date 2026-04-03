// Challenge 3 tests - Single-byte XOR cipher
extern "C" {
#include "ch01_hex_base64.h"
#include "ch03_single_byte_xor.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// main test: crack single-byte XOR with data from cryptopals.com
TEST(Ch03, SingleByteXOR)
{
    const char *hex_input =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    // decode hex to bytes
    uint8_t cipher[64];
    int len = hex_to_bytes(hex_input, cipher, sizeof(cipher));
    ASSERT_GT(len, 0);

    // try all 256 keys and pick the best
    uint8_t plaintext[64];
    xor_crack_result result = crack_single_byte_xor(cipher, len, plaintext);
    ASSERT_GT(result.score, 0);

    // print the decrypted message
    plaintext[len] = '\0';
    printf("  key=0x%02X char='%c' plaintext: %s\n",
           result.key, result.key, plaintext);
}

// english text should score higher than random garbage
TEST(Ch03, ScoreEnglish)
{
    const uint8_t english[] = "this is a normal english sentence";
    const uint8_t garbage[] = {0xFF, 0x01, 0xAB, 0xCD, 0x99, 0x88};

    float s1 = score_english(english, sizeof(english) - 1);
    float s2 = score_english(garbage, sizeof(garbage));
    EXPECT_GT(s1, s2);
}
