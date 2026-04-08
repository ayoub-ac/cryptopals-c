// Challenge 19 - Break fixed-nonce CTR mode using substitutions
// https://cryptopals.com/sets/3/challenges/19
#include "ch19_fixed_nonce_ctr.h"
#include "ch01_hex_base64.h"
#include "ch03_single_byte_xor.h"
#include "ch18_aes_ctr.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

// the 40 base64-encoded plaintexts from cryptopals
static const char *plaintexts_b64[] = {
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
};

#define NUM_TEXTS 40

static uint8_t fixed_key[16];
static int key_initialized = 0;

static void ensure_key(void)
{
    if (!key_initialized) {
        srand(time(NULL));
        for (int i = 0; i < 16; i++)
            fixed_key[i] = rand() % 256;
        key_initialized = 1;
    }
}

int encrypt_fixed_nonce(uint8_t ciphers[][128], int *cipher_lens, int max_count)
{
    ensure_key();

    int count = NUM_TEXTS < max_count ? NUM_TEXTS : max_count;

    for (int i = 0; i < count; i++) {
        // decode the base64 plaintext
        uint8_t plain[128];
        int plain_len = base64_to_bytes(plaintexts_b64[i], plain, sizeof(plain));
        if (plain_len < 0) return -1;

        // encrypt with same key and nonce=0
        int clen = aes_128_ctr(plain, plain_len, fixed_key, 0,
                               ciphers[i], 128);
        if (clen < 0) return -1;
        cipher_lens[i] = clen;
    }

    return count;
}

int recover_keystream(const uint8_t ciphers[][128], const int *cipher_lens,
                      int count, uint8_t *keystream, int max_keystream)
{
    // find the shortest cipher length so we can attack each column
    int min_len = cipher_lens[0];
    for (int i = 1; i < count; i++) {
        if (cipher_lens[i] < min_len) min_len = cipher_lens[i];
    }
    if (min_len > max_keystream) min_len = max_keystream;

    // for each column, all ciphers used the same keystream byte
    // so it's basically a single-byte XOR over a "column buffer"
    uint8_t column[64];
    uint8_t tmp[64];

    for (int col = 0; col < min_len; col++) {
        for (int row = 0; row < count; row++) {
            column[row] = ciphers[row][col];
        }

        // crack as a single-byte XOR
        xor_crack_result r = crack_single_byte_xor(column, count, tmp);
        keystream[col] = r.key;
    }

    return min_len;
}
