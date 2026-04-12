// Challenge 17 - The CBC padding oracle
// https://cryptopals.com/sets/3/challenges/17
//
// Attack AES-CBC when the server leaks whether PKCS#7 padding is valid.
// For each byte of plaintext we make ~128 oracle queries to recover it.
#include "ch17_padding_oracle.h"
#include "ch10_aes_cbc.h"
#include "ch09_pkcs7.h"
#include "ch01_hex_base64.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define BLOCK 16

static const char *plaintexts_b64[10] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

static uint8_t server_key[BLOCK];
static int key_initialized = 0;

static void ensure_key(void)
{
    if (!key_initialized) {
        srand((unsigned)time(NULL));
        for (int i = 0; i < BLOCK; i++)
            server_key[i] = rand() % 256;
        key_initialized = 1;
    }
}

// pick one of the 10 plaintexts, random IV, encrypt with fixed key
int padding_oracle_encrypt(uint8_t *iv_out, uint8_t *cipher_out, size_t cipher_out_size)
{
    ensure_key();

    int choice = rand() % 10;

    uint8_t plain[256];
    int plain_len = base64_to_bytes(plaintexts_b64[choice], plain, sizeof(plain));
    if (plain_len < 0) return -1;

    for (int i = 0; i < BLOCK; i++)
        iv_out[i] = rand() % 256;

    return aes_128_cbc_encrypt(plain, (size_t)plain_len,
                               server_key, iv_out, cipher_out, cipher_out_size);
}

// the oracle: decrypt and return 1 if PKCS#7 padding is valid
int padding_oracle_check(const uint8_t *iv, const uint8_t *cipher, size_t cipher_len)
{
    ensure_key();

    uint8_t plain[512];
    int len = aes_128_cbc_decrypt(cipher, cipher_len,
                                  server_key, iv, plain, sizeof(plain));
    return (len >= 0) ? 1 : 0;
}

// recover intermediate[] = AES_decrypt(c2) byte by byte via the oracle.
// forged[] plays the role of "previous block"; we tweak it so (intermediate
// XOR forged) has valid PKCS#7, first 0x01, then 0x02 0x02, 0x03 0x03 0x03...
static int recover_intermediate(const uint8_t *c2, uint8_t *intermediate)
{
    uint8_t forged[BLOCK];
    memset(forged, 0, BLOCK);

    for (int i = BLOCK - 1; i >= 0; i--) {
        uint8_t pad_val = (uint8_t)(BLOCK - i);

        // set known trailing bytes so they produce pad_val in P2'
        for (int j = i + 1; j < BLOCK; j++)
            forged[j] = intermediate[j] ^ pad_val;

        int found = -1;
        for (int g = 0; g < 256; g++) {
            forged[i] = (uint8_t)g;

            if (padding_oracle_check(forged, c2, BLOCK) != 1)
                continue;

            // last byte only: pad could accidentally be 0x02 0x02 (or longer),
            // not 0x01. flip forged[14] and re-check — if still valid, only
            // byte 15 mattered so pad really was 0x01. for i < 15 this can't
            // happen because we've already pinned the trailing bytes.
            if (i == BLOCK - 1) {
                uint8_t saved = forged[BLOCK - 2];
                forged[BLOCK - 2] ^= 0x01;
                int still = padding_oracle_check(forged, c2, BLOCK);
                forged[BLOCK - 2] = saved;
                if (still != 1) continue;
            }

            found = g;
            break;
        }

        if (found < 0) return -1;

        intermediate[i] = (uint8_t)found ^ pad_val;
    }

    return 0;
}

// block by block: recover intermediate, XOR with real previous block (IV
// for block 0), strip padding at the end
int padding_oracle_decrypt(const uint8_t *iv, const uint8_t *cipher, size_t cipher_len,
                           uint8_t *out, size_t out_size)
{
    if (cipher_len == 0 || cipher_len % BLOCK != 0) return -1;
    if (cipher_len > out_size) return -1;

    size_t num_blocks = cipher_len / BLOCK;
    uint8_t intermediate[BLOCK];

    for (size_t b = 0; b < num_blocks; b++) {
        const uint8_t *c1 = (b == 0) ? iv : cipher + (b - 1) * BLOCK;
        const uint8_t *c2 = cipher + b * BLOCK;

        if (recover_intermediate(c2, intermediate) < 0)
            return -1;

        for (int i = 0; i < BLOCK; i++)
            out[b * BLOCK + i] = intermediate[i] ^ c1[i];
    }

    return pkcs7_unpad(out, cipher_len);
}
