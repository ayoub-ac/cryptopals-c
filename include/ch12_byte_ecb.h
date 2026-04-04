#ifndef CH12_BYTE_ECB_H
#define CH12_BYTE_ECB_H

#include <stdint.h>
#include <stddef.h>

// oracle: appends unknown string to your input, encrypts with consistent key
int ecb_oracle(const uint8_t *input, size_t input_len,
               uint8_t *out, size_t out_size);

// discover the block size by feeding increasing input
int discover_block_size(void);

// decrypt the unknown string byte by byte
int decrypt_ecb_simple(uint8_t *out, size_t out_size);

#endif
