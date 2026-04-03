// Challenge 8 tests - Detect AES in ECB mode
extern "C" {
#include "ch08_detect_ecb.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// find which line in 8.txt is ECB encrypted
TEST(Ch08, DetectECB)
{
    int line = detect_ecb_in_file("../data/8.txt");
    ASSERT_GE(line, 0);
    printf("  ECB detected on line: %d\n", line);
}

// buffer with repeated 16-byte blocks should be detected
TEST(Ch08, RepeatedBlocks)
{
    uint8_t data[32];
    for (int i = 0; i < 16; i++) {
        data[i] = (uint8_t)i;
        data[i + 16] = (uint8_t)i; // same block
    }
    EXPECT_EQ(count_repeated_blocks(data, 32, 16), 1);
}

TEST(Ch08, NoRepeatedBlocks)
{
    uint8_t data[32];
    for (int i = 0; i < 32; i++)
        data[i] = (uint8_t)i; // all different
    EXPECT_EQ(count_repeated_blocks(data, 32, 16), 0);
}
