// Challenge 22 - Crack an MT19937 seed
// https://cryptopals.com/sets/3/challenges/22
#include "ch22_mt_crack_seed.h"
#include "ch21_mersenne_twister.h"
#include <stdlib.h>
#include <time.h>

// simulate the cryptopals scenario:
// 1. wait some seconds
// 2. seed MT with unix time
// 3. wait some seconds again
// 4. return first output
// we skip the real wait and use offsets, but the seed is a real timestamp
uint32_t mt_seed_with_time(uint32_t *seed_out)
{
    uint32_t now = (uint32_t)time(NULL);

    // pretend we waited: shift the seed back a bit
    uint32_t wait_offset = 40 + (rand() % 960);
    uint32_t seed = now - wait_offset;

    mt_seed(seed);

    if (seed_out) *seed_out = seed;
    return mt_extract();
}

// brute force: try every timestamp in a window before "now"
// we know the seed is at most ~2000 seconds in the past
uint32_t crack_mt_seed(uint32_t output, uint32_t now)
{
    for (uint32_t candidate = now; candidate > now - 2000; candidate--) {
        mt_seed(candidate);
        if (mt_extract() == output)
            return candidate;
    }
    return 0;
}
