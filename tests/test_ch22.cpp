// Challenge 22 tests - Crack MT19937 seed
extern "C" {
#include "ch22_mt_crack_seed.h"
}
#include <gtest/gtest.h>
#include <ctime>
#include <cstdio>

// the attack should recover the exact seed used
TEST(Ch22, CrackTimeBasedSeed)
{
    uint32_t real_seed;
    uint32_t output = mt_seed_with_time(&real_seed);

    uint32_t now = (uint32_t)time(NULL);
    uint32_t found = crack_mt_seed(output, now);

    printf("  real seed:  %u\n", real_seed);
    printf("  found seed: %u\n", found);

    EXPECT_EQ(found, real_seed);
}
