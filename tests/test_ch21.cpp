// Challenge 21 tests - MT19937 Mersenne Twister RNG
extern "C" {
#include "ch21_mersenne_twister.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// check first few outputs with seed=0 against known MT19937 values
TEST(Ch21, SeedZero)
{
    mt_seed(0);

    // these are the canonical MT19937 outputs for seed=0
    uint32_t expected[] = {
        2357136044u, 2546248239u, 3071714933u,
        3626093760u, 2588848963u
    };

    for (int i = 0; i < 5; i++) {
        uint32_t got = mt_extract();
        EXPECT_EQ(got, expected[i]) << "mismatch at index " << i;
    }
}

// seed with a different value and check outputs
TEST(Ch21, SeedKnown)
{
    mt_seed(1);

    uint32_t expected[] = {
        1791095845u, 4282876139u, 3093770124u,
        4005303368u, 491263u
    };

    for (int i = 0; i < 5; i++) {
        uint32_t got = mt_extract();
        EXPECT_EQ(got, expected[i]) << "mismatch at index " << i;
    }
}

// re-seeding with the same value should produce the same sequence
TEST(Ch21, Reseed)
{
    mt_seed(42);
    uint32_t first = mt_extract();
    uint32_t second = mt_extract();

    mt_seed(42);
    EXPECT_EQ(mt_extract(), first);
    EXPECT_EQ(mt_extract(), second);
}

// extract more than 624 values to trigger a second twist
TEST(Ch21, SecondTwist)
{
    mt_seed(5489);

    // burn through the first 624 + a few more
    for (int i = 0; i < 700; i++)
        mt_extract();

    // just make sure it doesn't crash and returns something
    uint32_t val = mt_extract();
    EXPECT_NE(val, 0u);  // technically could be 0 but astronomically unlikely
    printf("  value after 700 extracts: %u\n", val);
}
