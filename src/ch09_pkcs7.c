/* Challenge 9 - PKCS#7 padding
   https://cryptopals.com/sets/2/challenges/9

   Block ciphers like AES need input to be a multiple of the block size (16).
   PKCS#7 pads by adding N bytes, each with value N.
   Example: block=16, data=12 bytes -> add 4 bytes of 0x04
   If data is already a multiple, add a full block of padding.
*/
#include "ch09_pkcs7.h"
#include <string.h>

// add padding: N bytes of value N where N = block_size - (len % block_size)
int pkcs7_pad(const uint8_t *data, size_t len, size_t block_size,
              uint8_t *out, size_t out_size)
{
    size_t pad = block_size - (len % block_size);
    size_t new_len = len + pad;

    if (new_len > out_size)
        return -1;

    // copy original data
    memcpy(out, data, len);

    // fill padding bytes with the padding length
    for (size_t i = 0; i < pad; i++)
        out[len + i] = (uint8_t)pad;

    return (int)new_len;
}

// validate and remove padding
// last byte tells us how many padding bytes there are
int pkcs7_unpad(const uint8_t *data, size_t len)
{
    if (len == 0) return -1;

    uint8_t pad = data[len - 1]; // last byte = padding length

    if (pad == 0 || pad > len)
        return -1;

    // check all padding bytes have the same value
    for (size_t i = 0; i < pad; i++) {
        if (data[len - 1 - i] != pad)
            return -1;
    }

    return (int)(len - pad);
}
