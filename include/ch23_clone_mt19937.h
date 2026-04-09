#ifndef CH23_CLONE_MT19937_H
#define CH23_CLONE_MT19937_H

#include <stdint.h>

// invert the MT19937 tempering transform on a single output word
uint32_t mt_untemper(uint32_t y);

// tap the global mt_extract() exactly 624 times, untemper each output
// to reconstruct the internal state, then write predict_count predicted
// values into predict_out
int mt_clone_and_predict(uint32_t *predict_out, int predict_count);

#endif
