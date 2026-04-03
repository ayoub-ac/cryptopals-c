/* Challenge 3 - Single-byte XOR cipher
   https://cryptopals.com/sets/1/challenges/3

   A message was encrypted by XORing every byte with the same key byte.
   We don't know which byte was used, but there are only 256 possibilities.
   Strategy: try all 256, score each result by english letter frequency,
   the one with the highest score is the answer.
*/
#include "ch03_single_byte_xor.h"

// how often each letter appears in english (%)
// 'e' is the most common (12.7%), 'z' the least (0.07%)
// source: https://en.wikipedia.org/wiki/Letter_frequency
static const float freq_table[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

// give a score to text based on how much it looks like english
// higher score = more likely to be english
float score_english(const uint8_t *data, size_t len)
{
    float score = 0.0f;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        if (c >= 'a' && c <= 'z')      score += freq_table[c - 'a'];
        else if (c >= 'A' && c <= 'Z')  score += freq_table[c - 'A'];
        else if (c == ' ')              score += 13.0f;   // space is very common
        else if (c < 32 || c > 126)     score -= 10.0f;   // not readable, penalize
    }
    return score;
}

// XOR every byte in data with the same single key byte
void single_byte_xor(const uint8_t *data, size_t len, uint8_t key, uint8_t *out)
{
    for (size_t i = 0; i < len; i++)
        out[i] = data[i] ^ key;
}

// try all 256 possible key bytes, return the best match
xor_crack_result crack_single_byte_xor(const uint8_t *cipher, size_t len, uint8_t *out_buf)
{
    xor_crack_result best;
    best.key = 0;
    best.score = -1000.0f;   // start very low so any real result beats it
    best.plaintext = out_buf;
    best.len = len;

    uint8_t attempt[4096];   // temp buffer to try each key

    for (int key = 0; key < 256; key++) {
        // decrypt with this key
        single_byte_xor(cipher, len, (uint8_t)key, attempt);

        // score the result
        float s = score_english(attempt, len);

        // if this is the best so far, save it
        if (s > best.score) {
            best.score = s;
            best.key = (uint8_t)key;
            for (size_t i = 0; i < len; i++)
                out_buf[i] = attempt[i];
        }
    }

    return best;
}
