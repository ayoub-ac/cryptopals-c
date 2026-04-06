/* Challenge 18 - AES-128-CTR (Counter mode)
   https://cryptopals.com/sets/3/challenges/18

   CTR turns a block cipher into a stream cipher.
   We build a keystream by encrypting nonce+counter blocks with ECB,
   then XOR that keystream with the plaintext/ciphertext.
   Same function encrypts and decrypts, which is pretty neat.
*/
#include "ch18_aes_ctr.h"
#include <openssl/evp.h>
#include <string.h>

#define AES_BLOCK 16

// encrypt one 16-byte block with raw AES-ECB (no padding)
static void ecb_block_encrypt(const uint8_t *in, const uint8_t *key, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len;
    EVP_EncryptUpdate(ctx, out, &len, in, AES_BLOCK);
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

int aes_128_ctr(const uint8_t *in, size_t in_len,
                const uint8_t *key,
                uint64_t nonce,
                uint8_t *out, size_t out_size)
{
    if (out_size < in_len) return -1;

    uint8_t counter_block[AES_BLOCK];
    uint8_t keystream[AES_BLOCK];

    // nonce goes in the first 8 bytes, counter in the last 8 (both little-endian)
    memcpy(counter_block, &nonce, 8);

    size_t offset = 0;
    uint64_t counter = 0;

    while (offset < in_len) {
        memcpy(counter_block + 8, &counter, 8);
        ecb_block_encrypt(counter_block, key, keystream);

        // XOR keystream with input, might be less than 16 bytes on the last block
        size_t chunk = in_len - offset;
        if (chunk > AES_BLOCK) chunk = AES_BLOCK;

        for (size_t i = 0; i < chunk; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        offset += chunk;
        counter++;
    }

    return (int)in_len;
}
