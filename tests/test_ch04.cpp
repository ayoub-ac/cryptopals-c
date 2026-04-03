// Challenge 4 tests - Detect single-character XOR
extern "C" {
#include "ch04_detect_xor.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// find which line in 4.txt was encrypted with single-byte XOR
TEST(Ch04, DetectSingleByteXOR)
{
    uint8_t plaintext[128];
    xor_crack_result result;
    detect_single_byte_xor("../data/4.txt", plaintext, &result);

    ASSERT_GT(result.score, 0);

    // print what we found
    plaintext[result.len] = '\0';
    printf("  key=0x%02X char='%c' plaintext: %s\n",
           result.key, result.key, plaintext);
}
