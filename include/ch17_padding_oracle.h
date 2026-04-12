#ifndef CH17_PADDING_ORACLE_H
#define CH17_PADDING_ORACLE_H

#include <stdint.h>
#include <stddef.h>

// pick a random plaintext, encrypt with AES-CBC under a fixed key
// writes iv (16 bytes) and ciphertext, returns ciphertext length or -1
int padding_oracle_encrypt(uint8_t *iv_out, uint8_t *cipher_out, size_t cipher_out_size);

// the oracle: decrypt and check if PKCS#7 padding is valid
// returns 1 if valid, 0 if invalid
int padding_oracle_check(const uint8_t *iv, const uint8_t *cipher, size_t cipher_len);

// attack: recover the plaintext using only the oracle
// returns plaintext length (without padding) or -1
int padding_oracle_decrypt(const uint8_t *iv, const uint8_t *cipher, size_t cipher_len,
                           uint8_t *out, size_t out_size);

#endif
