#ifndef CH14_BYTE_ECB_HARDER_H
#define CH14_BYTE_ECB_HARDER_H

#include <stdint.h>
#include <stddef.h>

// oracle: encrypts random_prefix + input + unknown_string with ECB
int ecb_oracle_harder(const uint8_t *input, size_t input_len,
                      uint8_t *out, size_t out_size);

// figure out how long the random prefix is
int find_prefix_length(void);

// decrypt the unknown string (same idea as ch12 but with prefix)
int decrypt_ecb_harder(uint8_t *out, size_t out_size);

#endif
