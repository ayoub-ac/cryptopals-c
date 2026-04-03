// Challenge 7 tests - AES in ECB mode
extern "C" {
#include "ch01_hex_base64.h"
#include "ch07_aes_ecb.h"
}
#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>

// main test: decrypt the file with key "YELLOW SUBMARINE"
TEST(Ch07, AES_ECB_Decrypt)
{
    uint8_t cipher[8192];
    int cipher_len = read_base64_file("../data/7.txt", cipher, sizeof(cipher));
    ASSERT_GT(cipher_len, 0);

    const uint8_t *key = (const uint8_t *)"YELLOW SUBMARINE";
    uint8_t plaintext[8192];
    int len = aes_128_ecb_decrypt(cipher, cipher_len, key, plaintext, sizeof(plaintext));
    ASSERT_GT(len, 0);

    plaintext[len] = '\0';
    printf("  first 60 chars: %.60s\n", plaintext);
}

// encrypt then decrypt should give back the original
TEST(Ch07, AES_ECB_RoundTrip)
{
    const uint8_t *key = (const uint8_t *)"0123456789abcdef"; // 16 bytes
    const char *text = "hello from AES!!"; // exactly 16 bytes

    uint8_t encrypted[64], decrypted[64];
    int enc_len = aes_128_ecb_encrypt((const uint8_t *)text, strlen(text),
                                      key, encrypted, sizeof(encrypted));
    ASSERT_GT(enc_len, 0);

    int dec_len = aes_128_ecb_decrypt(encrypted, enc_len, key, decrypted, sizeof(decrypted));
    ASSERT_GT(dec_len, 0);

    decrypted[dec_len] = '\0';
    EXPECT_STREQ((const char *)decrypted, text);
}
