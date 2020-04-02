// [project 1] fixed-point.c
// Beomju Kim

#include "threads/fixed-point.h"

/* Convert integer to 17.14 fixed point */
struct fixed_1714
fp_i2f(int32_t i) {
    struct fixed_1714 ret = {.val = i * FP1714_FACTOR};
    return ret;
}

/* Convert to integer rounding toward zero */
int32_t
fp_f2i_to_zero(struct fixed_1714 f) {
    return (int32_t)(f.val / FP1714_FACTOR);
}

/* Convert to integer rounding to nearest */
int32_t
fp_f2i_nearest(struct fixed_1714 f) {
    if(f.val >= 0) {
        return (int32_t)((f.val + FP1714_FACTOR / 2) / FP1714_FACTOR);
    }
    return (int32_t)((f.val - FP1714_FACTOR / 2) / FP1714_FACTOR);
}


/* Add two fixed point */
struct fixed_1714
fp_plus_ff(struct fixed_1714 f1, struct fixed_1714 f2) {
    struct fixed_1714 ret = {.val = f1.val + f2.val};
    return ret;
}

/* Add fixed point and integer */
struct fixed_1714
fp_plus_fi(struct fixed_1714 f, int32_t i) {
    return fp_plus_ff(f, fp_i2f(i));
}

/* Calculate f1-f2 */
struct fixed_1714
fp_minus_ff(struct fixed_1714 f1, struct fixed_1714 f2) {
    struct fixed_1714 ret = {.val = f1.val - f2.val};
    return ret;
}

/* Calculate f - i */
struct fixed_1714
fp_minus_fi(struct fixed_1714 f, int32_t i) {
    return fp_minus_ff(f, fp_i2f(i));
}

/* Multiply two fixed point */
struct fixed_1714
fp_mult_ff(struct fixed_1714 f1, struct fixed_1714 f2) {
    struct fixed_1714 ret = {.val = ((int64_t)f1.val) * f2.val / FP1714_FACTOR};
    return ret;
}

/* Multiply fixed point and integer */
struct fixed_1714
fp_mult_fi(struct fixed_1714 f, int32_t i) {
    struct fixed_1714 ret = {.val = f.val * i};
    return ret;
}

/* Divide f1 by f2 */
struct fixed_1714 fp_div_ff(struct fixed_1714 f1, struct fixed_1714 f2) {
    struct fixed_1714 ret = {.val = ((int64_t)f1.val) * FP1714_FACTOR / f2.val};
    return ret;
}

/* Divide fixed point by integer */
struct fixed_1714 fp_div_fi(struct fixed_1714 f, int32_t i) {
    struct fixed_1714 ret = {.val = f.val / i};
    return ret;
}


/* Clamp fixed point between min and max, asserting minval <= f <= maxval.
The fixed point is firstly converted by converter. */
int32_t
fp_clamp_i(struct fixed_1714 f, int32_t minval, int32_t maxval, int32_t (*converter)(struct fixed_1714)) {
    int32_t i = converter(f);

    if(i < minval) i = minval;
    else if(i > maxval) i = maxval;

    return i;
}

/* lerp function calculates x*(1-a) + y*a where a = dividend / divisor.
This is optimized to reduce error.
(a=0) x ------------> y (a=1) */
struct fixed_1714
fp_lerp_i(struct fixed_1714 x, struct fixed_1714 y, int32_t dividend, int32_t divisor) {
    return fp_div_fi(
        fp_plus_ff(
            fp_mult_fi(x, divisor - dividend),
            fp_mult_fi(y, dividend)
        ),
        divisor
    );
}
