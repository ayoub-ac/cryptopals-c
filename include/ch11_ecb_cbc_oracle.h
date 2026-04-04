#ifndef CH11_ECB_CBC_ORACLE_H
#define CH11_ECB_CBC_ORACLE_H

#include <stddef.h>
#include <stdint.h>

// encrypt with random key, randomly choosing ECB or CBC
// returns 0 for ECB, 1 for CBC (so we can verify our detection)
int encryption_oracle(const uint8_t *input, size_t input_len,
                      uint8_t *out, size_t *out_len);

// detect whether ciphertext was encrypted with ECB or CBC
// returns 0 for ECB, 1 for CBC
int detect_ecb_or_cbc(const uint8_t *cipher, size_t len);

#endif
