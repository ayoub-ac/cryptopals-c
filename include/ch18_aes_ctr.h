#ifndef CH18_AES_CTR_H
#define CH18_AES_CTR_H

#include <stddef.h>
#include <stdint.h>

// encrypt or decrypt using AES-128-CTR (same operation both ways)
int aes_128_ctr(const uint8_t *in, size_t in_len,
                const uint8_t *key,
                uint64_t nonce,
                uint8_t *out, size_t out_size);

#endif
