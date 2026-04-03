/* Challenge 6 - Break repeating-key XOR
   https://cryptopals.com/sets/1/challenges/6

   A file was encrypted with repeating-key XOR then base64 encoded.
   We need to find the key and decrypt it.

   Strategy:
   1. Guess key length using Hamming distance
   2. Split ciphertext into blocks of that length
   3. Transpose: group all 1st bytes, all 2nd bytes, etc.
   4. Crack each group as single-byte XOR (reuse ch03)
   5. Combine the single-byte keys to get the full key
*/
#include "ch06_break_repeating_xor.h"
#include "ch03_single_byte_xor.h"
#include "ch05_repeating_xor.h"

// count differing bits between two buffers
// XOR gives 1 for each different bit, then we count the 1s
int hamming_distance(const uint8_t *a, const uint8_t *b, size_t len)
{
    int distance = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t diff = a[i] ^ b[i]; // different bits become 1
        while (diff) {
            distance += diff & 1;   // check lowest bit
            diff >>= 1;             // shift to check next
        }
    }
    return distance;
}

// try keysizes 2 to 40, return the one with smallest normalized hamming distance
int guess_keysize(const uint8_t *data, size_t len)
{
    int best_keysize = 2;
    float best_score = 1000.0f;

    for (int ks = 2; ks <= 40 && ks * 4 <= (int)len; ks++) {
        // average hamming distance over several block pairs
        float total = 0.0f;
        int pairs = 0;
        for (int i = 0; i < 3; i++) {
            for (int j = i + 1; j < 4; j++) {
                total += hamming_distance(data + i * ks, data + j * ks, ks);
                pairs++;
            }
        }

        // normalize by keysize so different sizes are comparable
        float score = total / pairs / ks;

        if (score < best_score) {
            best_score = score;
            best_keysize = ks;
        }
    }

    return best_keysize;
}

// break the cipher: find key and decrypt
int break_repeating_key_xor(const uint8_t *cipher, size_t cipher_len,
                            uint8_t *key_out, size_t key_max,
                            uint8_t *plain_out, size_t plain_max)
{
    int keysize = guess_keysize(cipher, cipher_len);
    if (keysize > (int)key_max)
        return -1;

    // for each position in the key, collect all bytes at that position
    // and crack as single-byte XOR (reuse ch03)
    uint8_t block[4096];
    uint8_t block_out[4096];

    for (int k = 0; k < keysize; k++) {
        // transpose: collect every k-th byte
        size_t block_len = 0;
        for (size_t i = k; i < cipher_len; i += keysize)
            block[block_len++] = cipher[i];

        // crack this column
        xor_crack_result r = crack_single_byte_xor(block, block_len, block_out);
        key_out[k] = r.key;
    }

    // decrypt with the found key
    if (cipher_len > plain_max)
        return -1;

    repeating_key_xor(cipher, cipher_len, key_out, keysize, plain_out);

    return keysize;
}
