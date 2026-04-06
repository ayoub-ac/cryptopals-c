// Challenge 18 tests - AES-128-CTR mode
extern "C" {
#include "ch18_aes_ctr.h"
#include "ch01_hex_base64.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

// decrypt the ciphertext from the cryptopals challenge
TEST(Ch18, DecryptCryptopals)
{
    const char *b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    const uint8_t *key = (const uint8_t *)"YELLOW SUBMARINE";

    uint8_t cipher[256];
    int cipher_len = base64_to_bytes(b64, cipher, sizeof(cipher));
    ASSERT_GT(cipher_len, 0);

    uint8_t plain[256];
    int plain_len = aes_128_ctr(cipher, cipher_len, key, 0, plain, sizeof(plain));
    ASSERT_EQ(plain_len, cipher_len);

    plain[plain_len] = '\0';
    printf("  decrypted: %s\n", plain);

    EXPECT_TRUE(strncmp((char *)plain, "Yo, VIP", 7) == 0);
}

// CTR encrypt then decrypt should give back the original
TEST(Ch18, RoundTrip)
{
    const uint8_t *key = (const uint8_t *)"0123456789abcdef";
    const char *msg = "CTR mode is basically a stream cipher built from a block cipher!";
    size_t msg_len = strlen(msg);

    uint8_t cipher[256];
    int ct_len = aes_128_ctr((const uint8_t *)msg, msg_len, key, 42, cipher, sizeof(cipher));
    ASSERT_EQ((size_t)ct_len, msg_len);

    // ciphertext should differ from plaintext
    EXPECT_NE(memcmp(cipher, msg, msg_len), 0);

    uint8_t recovered[256];
    int pt_len = aes_128_ctr(cipher, ct_len, key, 42, recovered, sizeof(recovered));
    ASSERT_EQ((size_t)pt_len, msg_len);

    EXPECT_EQ(memcmp(recovered, msg, msg_len), 0);
}

// last block can be shorter than 16 bytes, make sure that works
TEST(Ch18, PartialBlock)
{
    const uint8_t *key = (const uint8_t *)"YELLOW SUBMARINE";
    const char *msg = "Hello";

    uint8_t cipher[64], plain[64];
    int ct_len = aes_128_ctr((const uint8_t *)msg, 5, key, 0, cipher, sizeof(cipher));
    ASSERT_EQ(ct_len, 5);

    int pt_len = aes_128_ctr(cipher, 5, key, 0, plain, sizeof(plain));
    ASSERT_EQ(pt_len, 5);
    EXPECT_EQ(memcmp(plain, msg, 5), 0);
}
