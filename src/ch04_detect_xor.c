/* Challenge 4 - Detect single-character XOR
   https://cryptopals.com/sets/1/challenges/4

   A file has 326 hex strings. One of them was encrypted
   with single-byte XOR. We need to find which one.

   Strategy: run crack_single_byte_xor (from ch03) on every line,
   keep the one with the highest english score.
*/
#include "ch04_detect_xor.h"
#include "ch01_hex_base64.h"
#include <stdio.h>
#include <string.h>

int detect_single_byte_xor(const char *filename, uint8_t *out_buf,
                           xor_crack_result *result)
{
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    result->key = 0;
    result->score = -1000.0f;
    result->plaintext = out_buf;
    result->len = 0;

    char line[256];
    uint8_t bytes[128];
    uint8_t attempt[128];

    // read one line at a time
    while (fgets(line, sizeof(line), f)) {
        // remove newline
        size_t slen = strlen(line);
        while (slen > 0 && (line[slen - 1] == '\n' || line[slen - 1] == '\r'))
            line[--slen] = '\0';

        if (slen == 0)
            continue;

        // decode hex to bytes
        int len = hex_to_bytes(line, bytes, sizeof(bytes));
        if (len < 0)
            continue;

        // try to crack this line
        xor_crack_result r = crack_single_byte_xor(bytes, len, attempt);

        // if this line scores better than anything so far, save it
        if (r.score > result->score) {
            result->score = r.score;
            result->key = r.key;
            result->len = r.len;
            for (size_t i = 0; i < r.len; i++)
                out_buf[i] = attempt[i];
        }
    }

    fclose(f);
    return 0;
}
