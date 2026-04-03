#ifndef CH09_PKCS7_H
#define CH09_PKCS7_H

#include <stddef.h>
#include <stdint.h>

// add PKCS#7 padding to make data a multiple of block_size
// returns new length (with padding) or -1 on error
int pkcs7_pad(const uint8_t *data, size_t len, size_t block_size,
              uint8_t *out, size_t out_size);

// remove and validate PKCS#7 padding
// returns length without padding, or -1 if padding is invalid
int pkcs7_unpad(const uint8_t *data, size_t len);

#endif
