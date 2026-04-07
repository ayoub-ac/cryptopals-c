// Challenge 24 - Create the MT19937 stream cipher and break it
// https://cryptopals.com/sets/3/challenges/24
#include "ch24_mt_stream_cipher.h"
#include "ch21_mersenne_twister.h"
#include <string.h>

// stream cipher using MT19937 as keystream
// each MT output gives us 4 bytes of keystream
void mt_stream_cipher(uint16_t key, const uint8_t *in, size_t len, uint8_t *out)
{
    mt_seed((uint32_t)key);

    size_t i = 0;
    while (i < len) {
        uint32_t k = mt_extract();
        // use the 4 bytes of the 32-bit value as keystream
        for (int j = 0; j < 4 && i < len; j++, i++) {
            uint8_t kb = (k >> (j * 8)) & 0xff;
            out[i] = in[i] ^ kb;
        }
    }
}

// brute force the 16-bit key (only 65536 possibilities)
// we know part of the plaintext, so we decrypt and check if it matches
int crack_mt_stream(const uint8_t *cipher, size_t cipher_len,
                    const char *known_plaintext, size_t known_offset,
                    uint16_t *key_out)
{
    size_t known_len = strlen(known_plaintext);
    if (known_offset + known_len > cipher_len) return -1;

    uint8_t buf[1024];

    for (uint32_t k = 0; k <= 0xffff; k++) {
        mt_stream_cipher((uint16_t)k, cipher, cipher_len, buf);
        if (memcmp(buf + known_offset, known_plaintext, known_len) == 0) {
            if (key_out) *key_out = (uint16_t)k;
            return 0;
        }
    }

    return -1;
}
