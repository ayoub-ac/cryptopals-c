/* Challenge 2 - Fixed XOR
   https://cryptopals.com/sets/1/challenges/2

   Strategy: hex -> raw bytes -> XOR byte by byte -> hex

   XOR (^) compares two bits: if different = 1, if same = 0
   Key property: a ^ b ^ b = a (XOR cancels itself)
*/
#include "ch02_fixed_xor.h"

// XOR two buffers of the same length, byte by byte
// a[0]^b[0] goes to out[0], a[1]^b[1] goes to out[1], etc.
int fixed_xor(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ b[i];

    return (int)len;
}

// table to convert nibble value (0-15) to hex char ('0'-'f')
static const char hex_chars[] = "0123456789abcdef";

// convert raw bytes to hex string (inverse of hex_to_bytes from ch01)
// each byte becomes 2 hex chars: byte 0x4F -> "4f"
int bytes_to_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    if (len * 2 + 1 > out_size) // each byte = 2 chars + '\0'
        return -1;

    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_chars[(data[i] >> 4) & 0x0F]; // upper nibble
        out[i * 2 + 1] = hex_chars[data[i] & 0x0F];        // lower nibble
    }

    out[len * 2] = '\0';
    return (int)(len * 2);
}
