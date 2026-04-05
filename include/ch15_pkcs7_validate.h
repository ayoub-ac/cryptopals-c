#ifndef CH15_PKCS7_VALIDATE_H
#define CH15_PKCS7_VALIDATE_H

#include <stdint.h>
#include <stddef.h>

// validate pkcs7 padding and strip it, returns length without padding or -1
int pkcs7_validate_and_strip(const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_size);

#endif
