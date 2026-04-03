#ifndef CH07_AES_ECB_H
#define CH07_AES_ECB_H

#include <stddef.h>
#include <stdint.h>

// decrypt data encrypted with AES-128-ECB using OpenSSL
int aes_128_ecb_decrypt(const uint8_t *cipher, size_t cipher_len,
                        const uint8_t *key,
                        uint8_t *out, size_t out_size);

// encrypt data with AES-128-ECB
int aes_128_ecb_encrypt(const uint8_t *plain, size_t plain_len,
                        const uint8_t *key,
                        uint8_t *out, size_t out_size);

#endif
