// Challenge 6 tests - Break repeating-key XOR
extern "C" {
#include "ch01_hex_base64.h"
#include "ch06_break_repeating_xor.h"
}
#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>

// verify hamming distance with the example from cryptopals
TEST(Ch06, HammingDistance)
{
    const char *a = "this is a test";
    const char *b = "wokka wokka!!!";
    int d = hamming_distance((const uint8_t *)a, (const uint8_t *)b, strlen(a));
    EXPECT_EQ(d, 37); // cryptopals says it should be 37
}

// main test: decrypt the file from cryptopals.com
TEST(Ch06, BreakRepeatingKeyXOR)
{
    // read and decode the base64 file
    uint8_t cipher[8192];
    int cipher_len = read_base64_file("../data/6.txt", cipher, sizeof(cipher));
    ASSERT_GT(cipher_len, 0);

    // break the cipher
    uint8_t key[64], plaintext[8192];
    int keysize = break_repeating_key_xor(cipher, cipher_len,
                                          key, sizeof(key),
                                          plaintext, sizeof(plaintext));
    ASSERT_GT(keysize, 0);

    // print what we found
    key[keysize] = '\0';
    plaintext[cipher_len] = '\0';
    printf("  key (%d bytes): \"%s\"\n", keysize, key);
    printf("  first 60 chars: %.60s\n", plaintext);
}
