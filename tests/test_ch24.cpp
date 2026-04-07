// Challenge 24 tests - MT19937 stream cipher
extern "C" {
#include "ch24_mt_stream_cipher.h"
}
#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>

// encrypt then decrypt should give the original
TEST(Ch24, RoundTrip)
{
    const char *text = "hello from MT19937 stream";
    size_t len = strlen(text);

    uint8_t cipher[64], plain[64];
    mt_stream_cipher(0x1234, (const uint8_t *)text, len, cipher);
    mt_stream_cipher(0x1234, cipher, len, plain);

    plain[len] = '\0';
    EXPECT_STREQ((const char *)plain, text);
}

// the attack: brute force the 16-bit key
TEST(Ch24, CrackKey)
{
    // build a plaintext: random prefix + known text
    uint16_t real_key = 0xACAB;
    const char *known = "AAAAAAAAAAAAAA";
    size_t prefix_len = 5 + (rand() % 10);

    uint8_t plain[64];
    for (size_t i = 0; i < prefix_len; i++)
        plain[i] = rand() % 256;
    memcpy(plain + prefix_len, known, strlen(known));
    size_t total = prefix_len + strlen(known);

    // encrypt
    uint8_t cipher[64];
    mt_stream_cipher(real_key, plain, total, cipher);

    // crack
    uint16_t found_key = 0;
    int ret = crack_mt_stream(cipher, total, known, prefix_len, &found_key);

    printf("  real key:  0x%04x\n", real_key);
    printf("  found key: 0x%04x\n", found_key);

    ASSERT_EQ(ret, 0);
    EXPECT_EQ(found_key, real_key);
}
