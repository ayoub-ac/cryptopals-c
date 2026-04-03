// Challenge 10 tests - AES in CBC mode
extern "C" {
#include "ch01_hex_base64.h"
#include "ch10_aes_cbc.h"
}
#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>

// main test: decrypt 10.txt with key "YELLOW SUBMARINE" and IV of all zeros
TEST(Ch10, AES_CBC_Decrypt)
{
    uint8_t cipher[8192];
    int cipher_len = read_base64_file("../data/10.txt", cipher, sizeof(cipher));
    ASSERT_GT(cipher_len, 0);

    const uint8_t *key = (const uint8_t *)"YELLOW SUBMARINE";
    uint8_t iv[16] = {0}; // all zeros as specified
    uint8_t plaintext[8192];

    int len = aes_128_cbc_decrypt(cipher, cipher_len, key, iv,
                                  plaintext, sizeof(plaintext));
    ASSERT_GT(len, 0);

    plaintext[len] = '\0';
    printf("  first 60 chars: %.60s\n", plaintext);
}

// encrypt then decrypt should give back the original
TEST(Ch10, AES_CBC_RoundTrip)
{
    const uint8_t *key = (const uint8_t *)"0123456789abcdef";
    const uint8_t iv[16] = {0};
    const char *text = "testing CBC mode with some text!!"; // 32 bytes

    uint8_t encrypted[64], decrypted[64];

    int enc_len = aes_128_cbc_encrypt((const uint8_t *)text, strlen(text),
                                      key, iv, encrypted, sizeof(encrypted));
    ASSERT_GT(enc_len, 0);

    int dec_len = aes_128_cbc_decrypt(encrypted, enc_len,
                                      key, iv, decrypted, sizeof(decrypted));
    ASSERT_GT(dec_len, 0);

    decrypted[dec_len] = '\0';
    EXPECT_STREQ((const char *)decrypted, text);
}
