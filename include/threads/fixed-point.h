// [project 1] fixed-point.h
// Beomju Kim

#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

/* [project 1] Wrapper structure of 17.14 fixed-point
to prevent mistakes of confusing with integer variables */
struct fixed_1714 {
    int32_t val;
};

#define FP1714_FACTOR ((int32_t)(1<<14))

// converters

struct fixed_1714 fp_i2f(int32_t i);
int32_t fp_f2i_to_zero(struct fixed_1714 f);
int32_t fp_f2i_nearest(struct fixed_1714 f);

// basic operators mentioned on casys-kaist pintos docs

struct fixed_1714 fp_plus_ff(struct fixed_1714 f1, struct fixed_1714 f2);
struct fixed_1714 fp_plus_fi(struct fixed_1714 f, int32_t i);

struct fixed_1714 fp_minus_ff(struct fixed_1714 f1, struct fixed_1714 f2);
struct fixed_1714 fp_minus_fi(struct fixed_1714 f, int32_t i);

struct fixed_1714 fp_mult_ff(struct fixed_1714 f1, struct fixed_1714 f2);
struct fixed_1714 fp_mult_fi(struct fixed_1714 f, int32_t i);

struct fixed_1714 fp_div_ff(struct fixed_1714 f1, struct fixed_1714 f2);
struct fixed_1714 fp_div_fi(struct fixed_1714 f, int32_t i);

// advanced operators

int32_t fp_clamp_i(struct fixed_1714 f, int32_t minval, int32_t maxval, int32_t (*converter)(struct fixed_1714));
struct fixed_1714 fp_lerp_i(struct fixed_1714 x, struct fixed_1714 y, int32_t dividend, int32_t divisor);

#endif // THREADS_FIXED_POINT_H