#ifndef CH04_DETECT_XOR_H
#define CH04_DETECT_XOR_H

#include <stddef.h>
#include <stdint.h>
#include "ch03_single_byte_xor.h"

// read lines from a hex file, try to crack each one,
// return the line with the best english score
int detect_single_byte_xor(const char *filename, uint8_t *out_buf,
                           xor_crack_result *result);

#endif
