#ifndef CH06_BREAK_REPEATING_XOR_H
#define CH06_BREAK_REPEATING_XOR_H

#include <stddef.h>
#include <stdint.h>

// count the number of bits that differ between two buffers
int hamming_distance(const uint8_t *a, const uint8_t *b, size_t len);

// guess the key length by finding the keysize with smallest hamming distance
int guess_keysize(const uint8_t *data, size_t len);

// break repeating-key XOR: find the key and decrypt
// returns key length, writes key to key_out and plaintext to plain_out
int break_repeating_key_xor(const uint8_t *cipher, size_t cipher_len,
                            uint8_t *key_out, size_t key_max,
                            uint8_t *plain_out, size_t plain_max);

#endif
