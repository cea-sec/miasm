#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

/*

Big number library - arithmetic on multiple-precision unsigned integers.

This library is an implementation of arithmetic on arbitrarily large integers.

The difference between this and other implementations, is that the data structure
has optimal memory utilization (i.e. a 1024 bit integer takes up 128 bytes RAM),
and all memory is allocated statically: no dynamic allocation for better or worse.

Primary goals are correctness, clarity of code and clean, portable implementation.
Secondary goal is a memory footprint small enough to make it suitable for use in
embedded applications.


The current state is correct functionality and adequate performance.
There may well be room for performance-optimizations and improvements.

Source: https://github.com/kokke/tiny-bignum-c

Code slightly modified to support ast generation calculus style from Expr.

*/

#include <stdint.h>
#include <assert.h>


/* This macro defines the word size in bytes of the array that constitutes the big-number data structure. */
#ifndef WORD_SIZE
  #define WORD_SIZE 4
#endif

#define BN_BYTE_SIZE 32

#define BN_BIT_SIZE ((BN_BYTE_SIZE) * 8)

/* Size of big-numbers in bytes */
//#define BN_ARRAY_SIZE    (128 / WORD_SIZE)
#define BN_ARRAY_SIZE    (BN_BYTE_SIZE / WORD_SIZE)


/* Here comes the compile-time specialization for how large the underlying array size should be. */
/* The choices are 1, 2 and 4 bytes in size with uint32, uint64 for WORD_SIZE==4, as temporary. */
#ifndef WORD_SIZE
  #error Must define WORD_SIZE to be 1, 2, 4
#elif (WORD_SIZE == 1)
  /* Data type of array in structure */
  #define DTYPE                    uint8_t
  #define DTYPE_SIGNED             int8_t
  /* bitmask for getting MSB */
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80))
  /* Data-type larger than DTYPE, for holding intermediate results of calculations */
  #define DTYPE_TMP                uint32_t
  /* sprintf format string */
  #define SPRINTF_FORMAT_STR       "%.02x"
  #define SSCANF_FORMAT_STR        "%2hhx"
  /* Max value of integer type */
  #define MAX_VAL                  ((DTYPE_TMP)0xFF)
#elif (WORD_SIZE == 2)
  #define DTYPE                    uint16_t
  #define DTYPE_SIGNED             int16_t
  #define DTYPE_TMP                uint32_t
  #define DTYPE_MSB                ((DTYPE_TMP)(0x8000))
  #define SPRINTF_FORMAT_STR       "%.04x"
  #define SSCANF_FORMAT_STR        "%4hx"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFF)
#elif (WORD_SIZE == 4)
  #define DTYPE                    uint32_t
  #define DTYPE_SIGNED             int32_t
  #define DTYPE_TMP                uint64_t
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80000000))
  #define SPRINTF_FORMAT_STR       "%.08x"
  #define SSCANF_FORMAT_STR        "%8x"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFFFFFF)
#endif
#ifndef DTYPE
  #error DTYPE must be defined to uint8_t, uint16_t uint32_t or whatever
#endif


/* Custom assert macro - easy to disable */
#define require(p, msg) assert(p && #msg)


/* Data-holding structure: array of DTYPEs */
typedef struct bn
{
  DTYPE array[BN_ARRAY_SIZE];
} bn_t;



/* Tokens returned by bignum_cmp() for value comparison */
enum { SMALLER = -1, EQUAL = 0, LARGER = 1 };

/* Initialization functions: */
_MIASM_EXPORT bn_t bignum_init(void);
_MIASM_EXPORT bn_t bignum_from_int(DTYPE_TMP i);
_MIASM_EXPORT bn_t bignum_from_uint64(uint64_t i);
_MIASM_EXPORT int  bignum_to_int(bn_t n);
_MIASM_EXPORT uint64_t bignum_to_uint64(bn_t n);
_MIASM_EXPORT bn_t bignum_from_string(char* str, int nbytes);
_MIASM_EXPORT void bignum_to_string(bn_t n, char* str, int maxsize);


/* Basic arithmetic operations: */
_MIASM_EXPORT bn_t bignum_add(bn_t a, bn_t b); /* c = a + b */
_MIASM_EXPORT bn_t bignum_sub(bn_t a, bn_t b); /* c = a - b */
_MIASM_EXPORT bn_t bignum_mul(bn_t a, bn_t b); /* c = a * b */
_MIASM_EXPORT bn_t bignum_udiv(bn_t a, bn_t b); /* c = a / b */
_MIASM_EXPORT bn_t bignum_umod(bn_t a, bn_t b); /* c = a % b */
_MIASM_EXPORT bn_t bignum_sdiv(bn_t a, bn_t b, int size);
_MIASM_EXPORT bn_t bignum_smod(bn_t a, bn_t b, int size);
//void bignum_udivmod(struct bn* a, struct bn* b, struct bn* c, struct bn* d); /* c = a/b, d = a%b */



/* Bitwise operations: */
_MIASM_EXPORT bn_t bignum_and(bn_t a, bn_t b); /* c = a & b */
_MIASM_EXPORT bn_t bignum_or(bn_t a, bn_t b);  /* c = a | b */
_MIASM_EXPORT bn_t bignum_xor(bn_t a, bn_t b); /* c = a ^ b */
_MIASM_EXPORT bn_t bignum_lshift(bn_t a, int nbits); /* b = a << nbits */
_MIASM_EXPORT bn_t bignum_rshift(bn_t a, int nbits); /* b = a >> nbits */
_MIASM_EXPORT bn_t bignum_a_rshift(bn_t a, int size, int nbits); /* b = a a>> nbits */
_MIASM_EXPORT bn_t bignum_not(bn_t a); /* c = ~a */

/* Special operators and comparison */
_MIASM_EXPORT int bignum_cmp(bn_t a, bn_t b);                      /* Compare: returns LARGER, EQUAL or SMALLER */
_MIASM_EXPORT int bignum_is_equal(bn_t a, bn_t b);                 /* Return 1 if a == b else 0 */
_MIASM_EXPORT int bignum_is_inf_unsigned(bn_t a, bn_t b);          /* Return 1 if a <u b else 0 */
_MIASM_EXPORT int bignum_is_inf_equal_unsigned(bn_t a, bn_t b);    /* Return 1 if a <=u b else 0 */
_MIASM_EXPORT int bignum_is_inf_signed(bn_t a, bn_t b);            /* Return 1 if a <s b else 0 */
_MIASM_EXPORT int bignum_is_inf_equal_signed(bn_t a, bn_t b);      /* Return 1 if a <=s b else 0 */



_MIASM_EXPORT int  bignum_is_zero(bn_t n);                         /* For comparison with zero */
_MIASM_EXPORT bn_t bignum_inc(bn_t n);                             /* Increment: add one to n */
_MIASM_EXPORT bn_t bignum_dec(bn_t n);                             /* Decrement: subtract one from n */
//bn_t bignum_pow(bn_t a, bn_t b, bn_t c); /* Calculate a^b -- e.g. 2^10 => 1024 */
//bn_t bignum_isqrt(bn_t a, bn_t b);             /* Integer square root -- e.g. isqrt(5) => 2*/
_MIASM_EXPORT int bignum_cntleadzeros(bn_t n, int size);
_MIASM_EXPORT int bignum_cnttrailzeros(bn_t n, int size);
_MIASM_EXPORT bn_t bignum_assign(bn_t src);        /* Copy src into dst -- dst := src */
_MIASM_EXPORT bn_t bignum_mask(bn_t src, int bits);  /*  c = src & ((1<<bits) -1) */

_MIASM_EXPORT bn_t bignum_rol(bn_t a, int size, int nbits);
_MIASM_EXPORT bn_t bignum_ror(bn_t a, int size, int nbits);
_MIASM_EXPORT int bignum_getbit(bn_t a, int pos);

#endif /* #ifndef __BIGNUM_H__ */


