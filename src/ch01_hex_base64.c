/* Challenge 1 - Hex to Base64
   https://cryptopals.com/sets/1/challenges/1

   Hex and base64 are just different ways to represent bytes.
   To convert between them we decode to raw bytes first,
   then encode to the target format: hex -> bytes -> base64
*/
#include "ch01_hex_base64.h"
#include <string.h>

// convert a single hex char to its value (0-15), -1 if invalid
static int hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// decode hex string to raw bytes
int hex_to_bytes(const char *hex_str, uint8_t *out, size_t out_size)
{
    size_t hex_len = strlen(hex_str);

    if (hex_len % 2 != 0) // 2 hex chars = 1 byte, so length must be even
        return -1;

    size_t num_bytes = hex_len / 2;
    if (num_bytes > out_size)
        return -1;

    for (size_t i = 0; i < num_bytes; i++) {
        int hi = hex_char_to_val(hex_str[i * 2]);       // upper nibble
        int lo = hex_char_to_val(hex_str[i * 2 + 1]);   // lower nibble

        if (hi < 0 || lo < 0)
            return -1;

        out[i] = (uint8_t)((hi << 4) | lo); // combine into one byte
    }

    return (int)num_bytes;
}

// base64 table: 64 chars, each represents 6 bits
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// encode raw bytes to base64
int bytes_to_base64(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    size_t out_len = 4 * ((len + 2) / 3); // every 3 bytes become 4 base64 chars
    if (out_len + 1 > out_size)
        return -1;

    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        // read 3 bytes (pad with 0 if not enough)
        uint32_t a = (i < len) ? data[i++] : 0;
        uint32_t b = (i < len) ? data[i++] : 0;
        uint32_t c = (i < len) ? data[i++] : 0;

        // join 3 bytes into one 24-bit number
        uint32_t triple = (a << 16) | (b << 8) | c;

        // split into 4 groups of 6 bits, look up each in table
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = b64_table[(triple >> 6)  & 0x3F];
        out[j++] = b64_table[triple         & 0x3F];
    }

    // if input length wasn't multiple of 3, add '=' padding
    size_t remainder = len % 3;
    if (remainder == 1) { out[j - 1] = '='; out[j - 2] = '='; }
    else if (remainder == 2) { out[j - 1] = '='; }

    out[j] = '\0';
    return (int)j;
}

// full conversion: hex -> bytes -> base64
int hex_to_base64(const char *hex_str, char *out, size_t out_size)
{
    size_t num_bytes = strlen(hex_str) / 2;

    uint8_t buf[4096];
    if (num_bytes > sizeof(buf))
        return -1;

    int n = hex_to_bytes(hex_str, buf, sizeof(buf));
    if (n < 0)
        return -1;

    return bytes_to_base64(buf, (size_t)n, out, out_size);
}
