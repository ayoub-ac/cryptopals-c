/* Challenge 21 - Implement the MT19937 Mersenne Twister RNG
   https://cryptopals.com/sets/3/challenges/21

   Standard MT19937 with 32-bit word size.
   I mostly followed the pseudocode on Wikipedia for the constants.
*/
#include "ch21_mersenne_twister.h"

#define N 624
#define M 397
#define MATRIX_A   0x9908B0DFu
#define UPPER_MASK 0x80000000u  /* most significant bit */
#define LOWER_MASK 0x7FFFFFFFu  /* bits 0-30 */

static uint32_t mt[N];
static int index_ = N + 1;  /* means "not seeded yet" */

void mt_seed(uint32_t seed)
{
    mt[0] = seed;
    for (int i = 1; i < N; i++)
        mt[i] = 1812433253u * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i;
    index_ = N;  /* force twist on first extract */
}

/* generate the next 624 values (the "twist" step) */
static void mt_generate(void)
{
    for (int i = 0; i < N; i++) {
        uint32_t y = (mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK);
        mt[i] = mt[(i + M) % N] ^ (y >> 1);
        if (y & 1)
            mt[i] ^= MATRIX_A;
    }
    index_ = 0;
}

uint32_t mt_extract(void)
{
    if (index_ >= N)
        mt_generate();

    /* tempering transform - these constants are just part of the spec */
    uint32_t y = mt[index_++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9D2C5680u;
    y ^= (y << 15) & 0xEFC60000u;
    y ^= (y >> 18);
    return y;
}
