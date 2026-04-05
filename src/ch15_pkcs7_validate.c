// Challenge 15 - PKCS#7 padding validation
// https://cryptopals.com/sets/2/challenges/15
// Validate that the padding is correct and strip it.
// If the padding is bad, return an error.
#include "ch15_pkcs7_validate.h"
#include <string.h>

int pkcs7_validate_and_strip(const uint8_t *data, size_t len,
                             uint8_t *out, size_t out_size)
{
    if (len == 0) return -1;

    // last byte tells us the padding length
    uint8_t pad = data[len - 1];

    // padding value must be 1-16 and can't be bigger than the data
    if (pad == 0 || pad > 16 || pad > len)
        return -1;

    // check that all padding bytes have the same value
    for (size_t i = 0; i < pad; i++) {
        if (data[len - 1 - i] != pad)
            return -1;
    }

    size_t stripped = len - pad;
    if (stripped > out_size) return -1;

    memcpy(out, data, stripped);
    return (int)stripped;
}
