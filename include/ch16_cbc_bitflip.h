#ifndef CH16_CBC_BITFLIP_H
#define CH16_CBC_BITFLIP_H

#include <stdint.h>
#include <stddef.h>

// encrypt user input with prefix and suffix, using CBC
int bitflip_encrypt(const char *input, uint8_t *out, size_t out_size);

// decrypt and check if admin=true is there
int bitflip_check_admin(const uint8_t *cipher, size_t cipher_len);

// the attack: flip ciphertext bits to get admin
int cbc_bitflip_attack(uint8_t *cipher, size_t cipher_len);

#endif
