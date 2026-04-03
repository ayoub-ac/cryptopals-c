/* Challenge 5 - Repeating-key XOR
   https://cryptopals.com/sets/1/challenges/5

   Instead of XORing with a single byte (ch03), we use a multi-byte key
   that repeats. With key "ICE":
     byte 0 ^ 'I', byte 1 ^ 'C', byte 2 ^ 'E',
     byte 3 ^ 'I', byte 4 ^ 'C', byte 5 ^ 'E', ...

   This is basically the Vigenere cipher.
*/
#include "ch05_repeating_xor.h"

// XOR each byte with the corresponding key byte (key repeats using modulo)
void repeating_key_xor(const uint8_t *data, size_t data_len,
                       const uint8_t *key, size_t key_len,
                       uint8_t *out)
{
    for (size_t i = 0; i < data_len; i++)
        out[i] = data[i] ^ key[i % key_len]; // % makes the key cycle
}
