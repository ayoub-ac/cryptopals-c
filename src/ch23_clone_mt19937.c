// Challenge 23 - Clone an MT19937 RNG from its output
// https://cryptopals.com/sets/3/challenges/23
#include "ch23_clone_mt19937.h"
#include "ch21_mersenne_twister.h"

#define N          624
#define M          397
#define MATRIX_A   0x9908B0DFu
#define UPPER_MASK 0x80000000u
#define LOWER_MASK 0x7FFFFFFFu

// cloned MT state — separate from the global one in ch21
static uint32_t cloned_mt[N];
static int      cloned_index;

static void cloned_generate(void)
{
    for (int i = 0; i < N; i++) {
        uint32_t y = (cloned_mt[i] & UPPER_MASK) | (cloned_mt[(i + 1) % N] & LOWER_MASK);
        cloned_mt[i] = cloned_mt[(i + M) % N] ^ (y >> 1);
        if (y & 1)
            cloned_mt[i] ^= MATRIX_A;
    }
    cloned_index = 0;
}

static uint32_t cloned_extract(void)
{
    if (cloned_index >= N)
        cloned_generate();

    uint32_t y = cloned_mt[cloned_index++];
    y ^= (y >> 11);
    y ^= (y << 7)  & 0x9D2C5680u;
    y ^= (y << 15) & 0xEFC60000u;
    y ^= (y >> 18);
    return y;
}

// invert:  y = x ^ (x >> shift)
// top `shift` bits of y equal top `shift` bits of x (XOR with 0).
// each iteration recovers another `shift` bits from the top down.
// converges in ceil(32/shift) steps.
static uint32_t untemper_right(uint32_t y, int shift)
{
    uint32_t x = y;
    for (int i = shift; i < 32; i += shift)
        x = y ^ (x >> shift);
    return x;
}

// invert:  y = x ^ ((x << shift) & mask)
// bottom `shift` bits of y equal bottom `shift` bits of x.
// each iteration recovers another `shift` bits from the bottom up.
// converges in ceil(32/shift) steps.
static uint32_t untemper_left(uint32_t y, int shift, uint32_t mask)
{
    uint32_t x = y;
    for (int i = shift; i < 32; i += shift)
        x = y ^ ((x << shift) & mask);
    return x;
}

// reverse the four tempering steps in reverse order
uint32_t mt_untemper(uint32_t y)
{
    y = untemper_right(y, 18);
    y = untemper_left (y, 15, 0xEFC60000u);
    y = untemper_left (y, 7,  0x9D2C5680u);
    y = untemper_right(y, 11);
    return y;
}

int mt_clone_and_predict(uint32_t *predict_out, int predict_count)
{
    // collect 624 outputs from the victim and untemper each one back
    // to the raw state word it came from
    for (int i = 0; i < N; i++)
        cloned_mt[i] = mt_untemper(mt_extract());

    // after 624 extracts the victim's index == 624 and it will call
    // generate() on the next tap; set cloned_index == N so our clone
    // does the same twist in sync
    cloned_index = N;

    for (int i = 0; i < predict_count; i++)
        predict_out[i] = cloned_extract();

    return 0;
}
