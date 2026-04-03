#ifndef CH10_AES_CBC_H
#define CH10_AES_CBC_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

// decrypt AES-128-CBC (we implement CBC ourselves using ECB for each block)
int aes_128_cbc_decrypt(const uint8_t *cipher, size_t cipher_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint8_t *out, size_t out_size);

// encrypt AES-128-CBC
int aes_128_cbc_encrypt(const uint8_t *plain, size_t plain_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint8_t *out, size_t out_size);

#endif
