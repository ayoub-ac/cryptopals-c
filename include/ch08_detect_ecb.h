#ifndef CH08_DETECT_ECB_H
#define CH08_DETECT_ECB_H

#include <stddef.h>
#include <stdint.h>

// count how many 16-byte blocks are repeated in the data
int count_repeated_blocks(const uint8_t *data, size_t len, size_t block_size);

// find which line in a hex file is most likely ECB encrypted
// returns line number (0-based) or -1 if not found
int detect_ecb_in_file(const char *filename);

#endif
