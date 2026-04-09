// Challenge 23 tests - Clone MT19937 from output
extern "C" {
#include "ch21_mersenne_twister.h"
#include "ch23_clone_mt19937.h"
}
#include <gtest/gtest.h>
#include <cstdio>

// verify that untemper is the exact inverse of the tempering in mt_extract
TEST(Ch23, UntemperIsExactInverse)
{
    mt_seed(99999);
    for (int i = 0; i < 1000; i++) {
        uint32_t tempered   = mt_extract();
        uint32_t untampered = mt_untemper(tempered);
        // re-temper manually and check we get back the same value
        uint32_t y = untampered;
        y ^= (y >> 11);
        y ^= (y << 7)  & 0x9D2C5680u;
        y ^= (y << 15) & 0xEFC60000u;
        y ^= (y >> 18);
        EXPECT_EQ(y, tempered) << "untemper failed at output " << i;
    }
}

// tap a fresh RNG for 624 outputs, clone it, then verify the next
// 624 predicted values match the real outputs from the original RNG
TEST(Ch23, ClonePredictsFutureOutputs)
{
    mt_seed(0xDEADBEEF);

    const int PREDICT = 624;
    uint32_t predicted[PREDICT];

    mt_clone_and_predict(predicted, PREDICT);

    int mismatches = 0;
    for (int i = 0; i < PREDICT; i++) {
        uint32_t real = mt_extract();
        if (predicted[i] != real) {
            mismatches++;
            if (mismatches <= 3)
                printf("  mismatch at %d: predicted %u  real %u\n", i, predicted[i], real);
        }
    }

    printf("  mismatches: %d / %d\n", mismatches, PREDICT);
    EXPECT_EQ(mismatches, 0);
}
