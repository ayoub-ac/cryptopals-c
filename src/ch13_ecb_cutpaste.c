// Challenge 13 - ECB cut-and-paste
// https://cryptopals.com/sets/2/challenges/13
#include "ch13_ecb_cutpaste.h"
#include "ch07_aes_ecb.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

static uint8_t server_key[16];
static int key_initialized = 0;

static void ensure_key(void)
{
    if (!key_initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++)
            server_key[i] = rand() % 256;
        key_initialized = 1;
    }
}

// split something like "foo=bar&baz=qux" into pairs
int kv_parse(const char *input, kv_map *map)
{
    map->count = 0;
    const char *p = input;

    while (*p && map->count < 8) {
        kv_pair *kv = &map->pairs[map->count];

        // look for the = sign
        const char *eq = strchr(p, '=');
        if (!eq) return -1;

        size_t key_len = eq - p;
        if (key_len >= sizeof(kv->key)) return -1;
        memcpy(kv->key, p, key_len);
        kv->key[key_len] = '\0';

        // value goes until & or end of string
        const char *amp = strchr(eq + 1, '&');
        size_t val_len;
        if (amp) {
            val_len = amp - (eq + 1);
            p = amp + 1;
        } else {
            val_len = strlen(eq + 1);
            p = eq + 1 + val_len;
        }

        if (val_len >= sizeof(kv->value)) return -1;
        memcpy(kv->value, eq + 1, val_len);
        kv->value[val_len] = '\0';

        map->count++;
    }

    return map->count;
}

// build "email=X&uid=10&role=user", remove & and = from email
int profile_for(const char *email, char *out, size_t out_size)
{
    // strip dangerous chars so you can't inject role=admin directly
    size_t email_len = strlen(email);
    char clean[128];
    size_t j = 0;
    for (size_t i = 0; i < email_len && j < sizeof(clean) - 1; i++) {
        if (email[i] != '&' && email[i] != '=')
            clean[j++] = email[i];
    }
    clean[j] = '\0';

    return snprintf(out, out_size, "email=%s&uid=10&role=user", clean);
}

int encrypt_profile(const char *profile, uint8_t *out, size_t out_size)
{
    ensure_key();
    return aes_128_ecb_encrypt((const uint8_t *)profile, strlen(profile),
                               server_key, out, out_size);
}

int decrypt_profile(const uint8_t *cipher, size_t cipher_len, kv_map *map)
{
    ensure_key();
    uint8_t plain[256];
    int len = aes_128_ecb_decrypt(cipher, cipher_len, server_key,
                                  plain, sizeof(plain));
    if (len < 0) return -1;
    plain[len] = '\0';

    return kv_parse((const char *)plain, map);
}

int ecb_cut_and_paste(uint8_t *out, size_t *out_len)
{
    // I need "role=" to land right at the end of a block
    // so "user" ends up alone in the last block
    // "email=AAAA@AAAA.com&uid=10&role=" is exactly 32 bytes, perfect
    char profile1[128];
    profile_for("AAAA@AAAA.com", profile1, sizeof(profile1));

    uint8_t cipher1[256];
    int len1 = encrypt_profile(profile1, cipher1, sizeof(cipher1));
    if (len1 < 0) return -1;

    // now I need a block that encrypts "admin" with valid padding
    // "email=" takes 6 bytes, so 10 A's push "admin" to start of block 1
    char evil_email[64];
    memcpy(evil_email, "AAAAAAAAAAadmin", 15);
    // pad with 0x0b (11 bytes) so it looks like valid pkcs7
    for (int i = 0; i < 11; i++)
        evil_email[15 + i] = 0x0b;
    evil_email[26] = '\0';

    // can't use profile_for here because it would strip the padding bytes
    char profile2[128];
    int plen = snprintf(profile2, sizeof(profile2), "email=");
    memcpy(profile2 + plen, evil_email, 26);
    plen += 26;
    plen += snprintf(profile2 + plen, sizeof(profile2) - plen, "&uid=10&role=user");

    uint8_t cipher2[256];
    int len2 = aes_128_ecb_encrypt((const uint8_t *)profile2, plen,
                                   server_key, cipher2, sizeof(cipher2));
    if (len2 < 0) return -1;

    // now just glue the pieces: first 2 blocks + the admin block
    memcpy(out, cipher1, 32);
    memcpy(out + 32, cipher2 + 16, 16);

    *out_len = 48;
    return 0;
}
