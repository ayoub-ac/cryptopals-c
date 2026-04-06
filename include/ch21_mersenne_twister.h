#ifndef CH21_MERSENNE_TWISTER_H
#define CH21_MERSENNE_TWISTER_H

#include <stdint.h>

// seed the MT19937 generator
void mt_seed(uint32_t seed);

// get the next 32-bit random number
uint32_t mt_extract(void);

#endif
