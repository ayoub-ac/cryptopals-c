#ifndef CH20_BREAK_FIXED_NONCE_CTR_H
#define CH20_BREAK_FIXED_NONCE_CTR_H

#include <stddef.h>
#include <stdint.h>

#define CH20_MAX_TEXTS 64
#define CH20_MAX_LEN   256

// load base64 plaintexts from a file (one per line), decode to bytes
// stores them in plains[i] with their lengths in plain_lens[i]
// returns the number of plaintexts loaded
int load_plaintexts(const char *filename,
                    uint8_t plains[][CH20_MAX_LEN], int *plain_lens,
                    int max_count);

// encrypt all plaintexts with the same key and nonce=0 (CTR)
int encrypt_all_fixed_nonce(const uint8_t plains[][CH20_MAX_LEN],
                            const int *plain_lens, int count,
                            uint8_t ciphers[][CH20_MAX_LEN]);

// truncate to shortest length and recover keystream column by column
// using single-byte XOR cracking with english frequency scoring
int recover_keystream_stat(const uint8_t ciphers[][CH20_MAX_LEN],
                           const int *cipher_lens, int count,
                           uint8_t *keystream, int max_keystream);

#endif
