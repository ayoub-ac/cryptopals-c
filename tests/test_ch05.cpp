// Challenge 5 tests - Repeating-key XOR
extern "C" {
#include "ch02_fixed_xor.h"
#include "ch05_repeating_xor.h"
}
#include <gtest/gtest.h>
#include <cstring>

// main test: encrypt with key "ICE" using data from cryptopals.com
TEST(Ch05, RepeatingKeyXOR)
{
    const char *plaintext =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    const char *key = "ICE";
    const char *expected =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622"
        "6324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b"
        "20283165286326302e27282f";

    size_t len = strlen(plaintext);
    uint8_t encrypted[256];
    repeating_key_xor((const uint8_t *)plaintext, len,
                      (const uint8_t *)key, strlen(key), encrypted);

    // convert result to hex and compare
    char hex_output[512];
    bytes_to_hex(encrypted, len, hex_output, sizeof(hex_output));
    EXPECT_STREQ(hex_output, expected);
}

// encrypt then decrypt should give back the original
TEST(Ch05, EncryptDecrypt)
{
    const char *text = "hello world";
    const char *key = "secret";
    size_t len = strlen(text);

    uint8_t encrypted[64], decrypted[64];
    repeating_key_xor((const uint8_t *)text, len,
                      (const uint8_t *)key, strlen(key), encrypted);
    repeating_key_xor(encrypted, len,
                      (const uint8_t *)key, strlen(key), decrypted);

    decrypted[len] = '\0';
    EXPECT_STREQ((const char *)decrypted, text);
}
