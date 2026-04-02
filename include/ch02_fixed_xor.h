#ifndef CH02_FIXED_XOR_H
#define CH02_FIXED_XOR_H

#include <stddef.h>
#include <stdint.h>

// XOR two byte buffers of the same length, result goes into out
int fixed_xor(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len);

// encode raw bytes to hex string (inverse of hex_to_bytes from ch01)
int bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size);

#endif
