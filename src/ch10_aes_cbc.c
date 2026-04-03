/* Challenge 10 - Implement CBC mode
   https://cryptopals.com/sets/2/challenges/10

   CBC (Cipher Block Chaining): each plaintext block is XORed with the
   previous ciphertext block before being encrypted. First block uses
   an IV (initialization vector) instead of a previous block.

   We implement CBC ourselves using raw AES-ECB for each block.
   Cryptopals says: "do not use OpenSSL's CBC code".

   Decrypt: ECB decrypt block -> XOR with previous ciphertext (or IV)
   Encrypt: XOR plaintext with previous ciphertext (or IV) -> ECB encrypt
*/
#include "ch10_aes_cbc.h"
#include "ch09_pkcs7.h"
#include <openssl/evp.h>
#include <string.h>

// raw AES-ECB for one 16-byte block (no padding, no chaining)
static void ecb_block_decrypt(const uint8_t *in, const uint8_t *key, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // we handle padding ourselves
    int len;
    EVP_DecryptUpdate(ctx, out, &len, in, AES_BLOCK_SIZE);
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

static void ecb_block_encrypt(const uint8_t *in, const uint8_t *key, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len;
    EVP_EncryptUpdate(ctx, out, &len, in, AES_BLOCK_SIZE);
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

// XOR two 16-byte blocks
static void xor_blocks(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        out[i] = a[i] ^ b[i];
}

int aes_128_cbc_decrypt(const uint8_t *cipher, size_t cipher_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint8_t *out, size_t out_size)
{
    if (cipher_len % AES_BLOCK_SIZE != 0 || cipher_len > out_size)
        return -1;

    size_t num_blocks = cipher_len / AES_BLOCK_SIZE;
    const uint8_t *prev = iv; // first block XORs with IV

    for (size_t i = 0; i < num_blocks; i++) {
        const uint8_t *block = cipher + i * AES_BLOCK_SIZE;
        uint8_t decrypted[AES_BLOCK_SIZE];

        ecb_block_decrypt(block, key, decrypted);             // step 1: ECB decrypt
        xor_blocks(decrypted, prev, out + i * AES_BLOCK_SIZE); // step 2: XOR with previous

        prev = block; // current ciphertext becomes "previous" for next block
    }

    // remove PKCS#7 padding
    return pkcs7_unpad(out, cipher_len);
}

int aes_128_cbc_encrypt(const uint8_t *plain, size_t plain_len,
                        const uint8_t *key, const uint8_t *iv,
                        uint8_t *out, size_t out_size)
{
    // pad first
    uint8_t padded[8192];
    int padded_len = pkcs7_pad(plain, plain_len, AES_BLOCK_SIZE,
                               padded, sizeof(padded));
    if (padded_len < 0 || (size_t)padded_len > out_size)
        return -1;

    size_t num_blocks = padded_len / AES_BLOCK_SIZE;
    const uint8_t *prev = iv;

    for (size_t i = 0; i < num_blocks; i++) {
        uint8_t xored[AES_BLOCK_SIZE];

        xor_blocks(padded + i * AES_BLOCK_SIZE, prev, xored); // step 1: XOR with previous
        ecb_block_encrypt(xored, key, out + i * AES_BLOCK_SIZE); // step 2: ECB encrypt

        prev = out + i * AES_BLOCK_SIZE; // current ciphertext becomes "previous"
    }

    return padded_len;
}
