#ifndef CH05_REPEATING_XOR_H
#define CH05_REPEATING_XOR_H

#include <stddef.h>
#include <stdint.h>

// XOR data with a repeating key (Vigenere cipher)
// key cycles: byte 0 ^ key[0], byte 1 ^ key[1], ..., byte N ^ key[N % key_len]
void repeating_key_xor(const uint8_t *data, size_t data_len,
                       const uint8_t *key, size_t key_len,
                       uint8_t *out);

#endif
