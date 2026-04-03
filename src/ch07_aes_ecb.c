/* Challenge 7 - AES in ECB mode
   https://cryptopals.com/sets/1/challenges/7

   AES-128-ECB: each 16-byte block is encrypted/decrypted independently.
   We use OpenSSL's EVP interface for the actual AES operations.
   The key for this challenge is "YELLOW SUBMARINE".
*/
#include "ch07_aes_ecb.h"
#include <openssl/evp.h>

int aes_128_ecb_decrypt(const uint8_t *cipher, size_t cipher_len,
                        const uint8_t *key,
                        uint8_t *out, size_t out_size)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_DecryptUpdate(ctx, out, &len, cipher, cipher_len);
    total = len;
    EVP_DecryptFinal_ex(ctx, out + total, &len);
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

int aes_128_ecb_encrypt(const uint8_t *plain, size_t plain_len,
                        const uint8_t *key,
                        uint8_t *out, size_t out_size)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, out, &len, plain, plain_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, out + total, &len);
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}
