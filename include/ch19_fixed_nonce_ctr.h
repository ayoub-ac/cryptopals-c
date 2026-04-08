#ifndef CH19_FIXED_NONCE_CTR_H
#define CH19_FIXED_NONCE_CTR_H

#include <stddef.h>
#include <stdint.h>

// encrypt all the plaintexts with the same key and nonce=0
// returns the number of ciphertexts produced
int encrypt_fixed_nonce(uint8_t ciphers[][128], int *cipher_lens,
                        int max_count);

// recover the keystream byte by byte using single-byte XOR cracking
// per column (all bytes at position i use the same keystream byte)
int recover_keystream(const uint8_t ciphers[][128], const int *cipher_lens,
                      int count, uint8_t *keystream, int max_keystream);

#endif
