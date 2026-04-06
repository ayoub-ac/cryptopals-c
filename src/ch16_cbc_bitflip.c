// Challenge 16 - CBC bitflipping attack
// https://cryptopals.com/sets/2/challenges/16
#include "ch16_cbc_bitflip.h"
#include "ch10_aes_cbc.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static uint8_t server_key[16];
static uint8_t server_iv[16];
static int key_initialized = 0;

static void ensure_key(void)
{
    if (!key_initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++) {
            server_key[i] = rand() % 256;
            server_iv[i] = rand() % 256;
        }
        key_initialized = 1;
    }
}

// encrypt: prefix + user input + suffix, stripping ; and = from input
int bitflip_encrypt(const char *input, uint8_t *out, size_t out_size)
{
    ensure_key();

    const char *prefix = "comment1=cooking%20MCs;userdata=";
    const char *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    // remove ; and = so you can't just type admin
    char clean[256];
    size_t j = 0;
    for (size_t i = 0; input[i] && j < sizeof(clean) - 1; i++) {
        if (input[i] == ';' || input[i] == '=') continue;
        clean[j++] = input[i];
    }
    clean[j] = '\0';

    char buf[512];
    int total = snprintf(buf, sizeof(buf), "%s%s%s", prefix, clean, suffix);

    return aes_128_cbc_encrypt((const uint8_t *)buf, total,
                               server_key, server_iv, out, out_size);
}

// decrypt and check if we got admin
int bitflip_check_admin(const uint8_t *cipher, size_t cipher_len)
{
    ensure_key();

    uint8_t plain[512];
    int len = aes_128_cbc_decrypt(cipher, cipher_len,
                                  server_key, server_iv, plain, sizeof(plain));
    if (len < 0) return 0;
    plain[len] = '\0';

    return strstr((const char *)plain, ";admin=true;") != NULL;
}

// flip bits in the ciphertext to turn X into ; and =
int cbc_bitflip_attack(uint8_t *cipher, size_t cipher_len)
{
    // the prefix is 32 bytes so our input starts at block 2
    // we sent "XadminXtrueX" where X is a placeholder
    // flipping bits in block 1 changes the same positions in block 2

    if (cipher_len < 48) return -1;

    cipher[16 + 0] ^= 'X' ^ ';';
    cipher[16 + 6] ^= 'X' ^ '=';
    cipher[16 + 11] ^= 'X' ^ ';';

    return 0;
}
