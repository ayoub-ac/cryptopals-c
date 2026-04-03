#ifndef CH03_SINGLE_BYTE_XOR_H
#define CH03_SINGLE_BYTE_XOR_H

#include <stddef.h>
#include <stdint.h>

// result of cracking a single-byte XOR
typedef struct {
    uint8_t key;        // the byte key that gave best score
    float score;        // how english-like the result is
    uint8_t *plaintext; // pointer to decrypted text
    size_t len;         // length of plaintext
} xor_crack_result;

// score text by english letter frequency (higher = more english)
float score_english(const uint8_t *data, size_t len);

// XOR every byte with the same key
void single_byte_xor(const uint8_t *data, size_t len, uint8_t key, uint8_t *out);

// try all 256 keys, return the one that produces most english-like text
xor_crack_result crack_single_byte_xor(const uint8_t *cipher, size_t len, uint8_t *out_buf);

#endif
