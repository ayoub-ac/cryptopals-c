#ifndef CH24_MT_STREAM_CIPHER_H
#define CH24_MT_STREAM_CIPHER_H

#include <stdint.h>
#include <stddef.h>

// encrypt or decrypt with MT19937 keystream (same operation)
void mt_stream_cipher(uint16_t key, const uint8_t *in, size_t len, uint8_t *out);

// recover the 16-bit key by brute force
int crack_mt_stream(const uint8_t *cipher, size_t cipher_len,
                    const char *known_plaintext, size_t known_offset,
                    uint16_t *key_out);

#endif
