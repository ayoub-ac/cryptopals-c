#ifndef CH22_MT_CRACK_SEED_H
#define CH22_MT_CRACK_SEED_H

#include <stdint.h>

// simulate: wait, seed with timestamp, wait, return first output
uint32_t mt_seed_with_time(uint32_t *seed_out);

// given an output, find the seed by trying recent timestamps
uint32_t crack_mt_seed(uint32_t output, uint32_t now);

#endif
