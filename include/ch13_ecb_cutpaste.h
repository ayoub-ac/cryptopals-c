#ifndef CH13_ECB_CUTPASTE_H
#define CH13_ECB_CUTPASTE_H

#include <stdint.h>
#include <stddef.h>

// parse "foo=bar&baz=qux" into key-value pairs
typedef struct {
    char key[32];
    char value[64];
} kv_pair;

typedef struct {
    kv_pair pairs[8];
    int count;
} kv_map;

int kv_parse(const char *input, kv_map *map);

// create a profile string for an email: "email=X&uid=10&role=user"
int profile_for(const char *email, char *out, size_t out_size);

// encrypt a profile string
int encrypt_profile(const char *profile, uint8_t *out, size_t out_size);

// decrypt and parse a profile
int decrypt_profile(const uint8_t *cipher, size_t cipher_len, kv_map *map);

// the attack: craft ciphertexts to make role=admin
int ecb_cut_and_paste(uint8_t *out, size_t *out_len);

#endif
