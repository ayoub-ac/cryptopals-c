/* Challenge 8 - Detect AES in ECB mode
   https://cryptopals.com/sets/1/challenges/8

   ECB encrypts each 16-byte block independently.
   If two plaintext blocks are the same, the ciphertext blocks
   will also be the same. We look for repeated 16-byte blocks.
*/
#include "ch08_detect_ecb.h"
#include "ch01_hex_base64.h"
#include <stdio.h>
#include <string.h>

// count how many 16-byte blocks appear more than once
int count_repeated_blocks(const uint8_t *data, size_t len, size_t block_size)
{
    size_t num_blocks = len / block_size;
    int repeats = 0;

    for (size_t i = 0; i < num_blocks; i++) {
        for (size_t j = i + 1; j < num_blocks; j++) {
            if (memcmp(data + i * block_size, data + j * block_size, block_size) == 0)
                repeats++;
        }
    }

    return repeats;
}

// read file of hex strings, find the one with repeated blocks
int detect_ecb_in_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char line[512];
    uint8_t bytes[256];
    int best_line = -1;
    int best_repeats = 0;
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        // remove newline
        size_t slen = strlen(line);
        while (slen > 0 && (line[slen - 1] == '\n' || line[slen - 1] == '\r'))
            line[--slen] = '\0';

        if (slen == 0) { line_num++; continue; }

        int len = hex_to_bytes(line, bytes, sizeof(bytes));
        if (len < 0) { line_num++; continue; }

        int repeats = count_repeated_blocks(bytes, len, 16);
        if (repeats > best_repeats) {
            best_repeats = repeats;
            best_line = line_num;
        }

        line_num++;
    }

    fclose(f);
    return best_line;
}
