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

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>
#include "bn.h"

/* Functions for shifting number in-place. */
static bn_t _lshift_one_bit(bn_t a);
static bn_t _rshift_one_bit(bn_t a);
static bn_t _lshift_word(bn_t a, int nwords);
static bn_t _rshift_word(bn_t a, int nwords);




/* Public / Exported functions. */
bn_t bignum_init(void)
{
	int i;
	bn_t n;

	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		n.array[i] = 0;
	}

	return n;
}


bn_t bignum_from_int(DTYPE_TMP i)
{
	bn_t n;

	n = bignum_init();
  /* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZE
 #if (WORD_SIZE == 1)
	n.array[0] = (i & 0x000000ff);
	n.array[1] = (i & 0x0000ff00) >> 8;
	n.array[2] = (i & 0x00ff0000) >> 16;
	n.array[3] = (i & 0xff000000) >> 24;
 #elif (WORD_SIZE == 2)
	n.array[0] = (i & 0x0000ffff);
	n.array[1] = (i & 0xffff0000) >> 16;
 #elif (WORD_SIZE == 4)
	n.array[0] = (DTYPE)i;
	DTYPE_TMP num_32 = 32;
	DTYPE_TMP tmp = i >> num_32; /* bit-shift with U64 operands to force 64-bit results */
	n.array[1] = (DTYPE)tmp;
 #endif
#endif

	return n;
}



bn_t bignum_from_uint64(uint64_t i)
{
	bn_t n;
	n = bignum_init();
  /* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZE
 #if (WORD_SIZE == 1)
	n.array[0] = (i & 0x000000ff);
	n.array[1] = (i & 0x0000ff00) >> 8;
	n.array[2] = (i & 0x00ff0000) >> 16;
	n.array[3] = (i & 0xff000000) >> 24;
 #elif (WORD_SIZE == 2)
	n.array[0] = (i & 0x0000ffff);
	n.array[1] = (i & 0xffff0000) >> 16;
 #elif (WORD_SIZE == 4)
	n.array[0] = (DTYPE)i;
	DTYPE_TMP num_32 = 32;
	DTYPE_TMP tmp = i >> num_32; /* bit-shift with U64 operands to force 64-bit results */
	n.array[1] = (DTYPE)tmp;
 #endif
#endif

	return n;
}





int bignum_to_int(bn_t n)
{

	int ret = 0;

	/* Endianness issue if machine is not little-endian? */
#if (WORD_SIZE == 1)
	ret += n.array[0];
	ret += n.array[1] << 8;
	ret += n.array[2] << 16;
	ret += n.array[3] << 24;
#elif (WORD_SIZE == 2)
	ret += n.array[0];
	ret += n.array[1] << 16;
#elif (WORD_SIZE == 4)
	ret += n.array[0];
#endif


	return ret;
}


uint64_t bignum_to_uint64(bn_t n)
{

	uint64_t ret = 0;

	/* Endianness issue if machine is not little-endian? */
#if (WORD_SIZE == 1)
	ret += (uint64_t)(n.array[0]);
	ret += (uint64_t)(n.array[1]) << 8;
	ret += (uint64_t)(n.array[2]) << 16;
	ret += (uint64_t)(n.array[3]) << 24;

	ret += (uint64_t)(n.array[4]) << 32;
	ret += (uint64_t)(n.array[5]) << 40;
	ret += (uint64_t)(n.array[6]) << 48;
	ret += (uint64_t)(n.array[7]) << 56;


#elif (WORD_SIZE == 2)
	ret += (uint64_t)(n.array[0]);
	ret += (uint64_t)(n.array[1]) << 16;
	ret += (uint64_t)(n.array[2]) << 32;
	ret += (uint64_t)(n.array[3]) << 48;
#elif (WORD_SIZE == 4)
	ret += n.array[0];
	ret += (uint64_t)(n.array[1]) << 32;
#endif

	return ret;
}




bn_t bignum_from_string(char* str, int nbytes)
{

	require(str, "str is null");
	require(nbytes > 0, "nbytes must be positive");
	require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");

	bn_t n;

	n = bignum_init();

	DTYPE tmp;                        /* DTYPE is defined in bn.h - uint{8,16,32,64}_t */
	int i = nbytes - (2 * WORD_SIZE); /* index into string */
	int j = 0;                        /* index into array */

	/* reading last hex-byte "MSB" from string first -> big endian */
	/* MSB ~= most significant byte / block ? :) */
	while (i >= 0) {
		tmp = 0;
		sscanf(&str[i], SSCANF_FORMAT_STR, &tmp);
		n.array[j] = tmp;
		i -= (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) back in the string. */
		j += 1;               /* step one element forward in the array. */
	}

	return n;
}

void bignum_to_string(bn_t n, char* str, int nbytes)
{
	require(str, "str is null");
	require(nbytes > 0, "nbytes must be positive");
	require((nbytes & 1) == 0, "string format must be in hex -> equal number of bytes");

	int j = BN_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
	int i = 0;                 /* index into string representation. */

	/* reading last array-element "MSB" first -> big endian */
	while ((j >= 0) && (nbytes > (i + 1))) {
		sprintf(&str[i], SPRINTF_FORMAT_STR, n.array[j]);
		i += (2 * WORD_SIZE); /* step WORD_SIZE hex-byte(s) forward in the string. */
		j -= 1;               /* step one element back in the array. */
	}

	/* Zero-terminate string */
	str[i] = 0;
}



bn_t bignum_dec(bn_t n)
{
	//require(n, "n is null");

	DTYPE tmp; /* copy of n */
	DTYPE res;

	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		tmp = n.array[i];
		res = tmp - 1;
		n.array[i] = res;

		if (!(res > tmp)) {
			break;
		}
	}

	return n;
}


bn_t bignum_inc(bn_t n)
{
	//require(n, "n is null");

	DTYPE res;
	DTYPE tmp; /* copy of n */

	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		tmp = n.array[i];
		res = tmp + 1;
		n.array[i] = res;

		if (res > tmp) {
			break;
		}
	}

	return n;
}



bn_t bignum_add(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");
	bn_t c;

	DTYPE_TMP tmp;
	int carry = 0;
	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		tmp = (DTYPE_TMP)a.array[i] + b.array[i] + carry;
		carry = (tmp > MAX_VAL);
		c.array[i] = (tmp & MAX_VAL);
	}

	return c;
}


bn_t bignum_sub(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");
	bn_t c;

	DTYPE_TMP res;
	DTYPE_TMP tmp1;
	DTYPE_TMP tmp2;
	int borrow = 0;
	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		tmp1 = (DTYPE_TMP)a.array[i] + (MAX_VAL + 1); /* + number_base */
		tmp2 = (DTYPE_TMP)b.array[i] + borrow;;
		res = (tmp1 - tmp2);
		c.array[i] = (DTYPE)(res & MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if number_base is 2^N */
		borrow = (res <= MAX_VAL);
	}

	return c;
}




bn_t bignum_mul(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");

	bn_t c;
	bn_t row;
	bn_t tmp;
	int i, j;

	c = bignum_init();

	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		row = bignum_init();

		for (j = 0; j < BN_ARRAY_SIZE; ++j) {
			if (i + j < BN_ARRAY_SIZE) {
				tmp = bignum_init();
				DTYPE_TMP intermediate = ((DTYPE_TMP)a.array[i] * (DTYPE_TMP)b.array[j]);
				tmp = bignum_from_int(intermediate);
				tmp = _lshift_word(tmp, i + j);
				row = bignum_add(tmp, row);
			}
		}
		c = bignum_add(c, row);
	}

	return c;
}


bn_t bignum_udiv(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");

	bn_t c;
	bn_t current;
	bn_t denom;
	bn_t tmp;

	current = bignum_from_int(1);               // int current = 1;
	denom = bignum_assign(b);                   // denom = b
	tmp = bignum_assign(a);                     // tmp   = a

	const DTYPE_TMP half_max = 1 + (DTYPE_TMP)(MAX_VAL / 2);
	bool overflow = false;

	while (bignum_cmp(denom, a) != LARGER) {    // while (denom <= a) {
		if (denom.array[BN_ARRAY_SIZE - 1] >= half_max) {
			overflow = true;
			break;
		}
		current = _lshift_one_bit(current);                //   current <<= 1;
		denom = _lshift_one_bit(denom);                  //   denom <<= 1;
	}
	if (!overflow) {
		denom = _rshift_one_bit(denom);                  // denom >>= 1;
		current = _rshift_one_bit(current);                // current >>= 1;
	}
	c = bignum_init();                             // int answer = 0;

	while (!bignum_is_zero(current)) {           // while (current != 0)
		if (bignum_cmp(tmp, denom) != SMALLER) {  //   if (dividend >= denom)
			tmp = bignum_sub(tmp, denom);         //     dividend -= denom;
			c = bignum_or(c, current);              //     answer |= current;
		}
		current = _rshift_one_bit(current);                //   current >>= 1;
		denom = _rshift_one_bit(denom);                  //   denom >>= 1;
	}                                           // return answer;

	return c;
}



bn_t bignum_lshift(bn_t a, int nbits)
{
	//require(a, "a is null");
	//require(b, "b is null");
	require(nbits >= 0, "no negative shifts");

	bn_t b;

	b = bignum_assign(a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;
	if (nwords != 0) {
		b = _lshift_word(b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}

	if (nbits != 0) {
		int i;
		for (i = (BN_ARRAY_SIZE - 1); i > 0; --i) {
			b.array[i] = (b.array[i] << nbits) | (b.array[i - 1] >> ((8 * WORD_SIZE) - nbits));
		}
		b.array[i] <<= nbits;
	}

	return b;
}


bn_t bignum_rshift(bn_t a, int nbits)
{
	//require(a, "a is null");
	//require(b, "b is null");
	require(nbits >= 0, "no negative shifts");

	bn_t b;

	b = bignum_assign(a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;

	if (nwords != 0) {
		b = _rshift_word(b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}
	if (nbits != 0) {
		int i;
		for (i = 0; i < (BN_ARRAY_SIZE - 1); ++i) {
			b.array[i] = (b.array[i] >> nbits) | (b.array[i + 1] << ((8 * WORD_SIZE) - nbits));
		}
		b.array[i] >>= nbits;
	}

	return b;
}



bn_t bignum_a_rshift(bn_t a, int size, int nbits)
{
	//require(a, "a is null");
	//require(b, "b is null");
	require(nbits >= 0, "no negative shifts");
	require(size > 0, "no negative shifts");

	bn_t b;
	bn_t tmp, mask;

	b = bignum_rshift(a, nbits);

	/* get sign bit */
	tmp = bignum_rshift(a, size - 1);
	tmp = bignum_mask(tmp, 1);

	if (!bignum_is_zero(tmp)) {
		/* generate sign propag */
		tmp = bignum_from_int(1);
		tmp = bignum_lshift(tmp, size);
		tmp = bignum_dec(tmp);

		mask = bignum_from_int(1);
		mask = bignum_lshift(mask, size - nbits);
		mask = bignum_dec(mask);

		tmp = bignum_xor(tmp, mask);
		b = bignum_or(b, tmp);
	}

	return b;
}

bn_t bignum_not(bn_t a)
{
	int i;
	bn_t b;

	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		b.array[i] = ~a.array[i];
	}

	return b;
}



bn_t bignum_umod(bn_t a, bn_t b)
{
	/*
	  Take divmod and throw away div part
	*/
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");

	bn_t c, d;
	bn_t tmp;

	/* c = (a / b) */
	c = bignum_udiv(a, b);
	/* tmp = (c * b) */
	tmp = bignum_mul(c, b);
	/* c = a - tmp */
	d = bignum_sub(a, tmp);
	return d;
}


bn_t bignum_and(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");
	bn_t c;

	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		c.array[i] = (a.array[i] & b.array[i]);
	}

	return c;
}


bn_t bignum_or(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");
	bn_t c;
	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		c.array[i] = (a.array[i] | b.array[i]);
	}

	return c;
}


bn_t bignum_xor(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");
	//require(c, "c is null");

	bn_t c;
	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		c.array[i] = (a.array[i] ^ b.array[i]);
	}
	return c;
}


int bignum_cmp(bn_t a, bn_t b)
{
	//require(a, "a is null");
	//require(b, "b is null");

	int i = BN_ARRAY_SIZE;
	do {
		i -= 1; /* Decrement first, to start with last array element */
		if (a.array[i] > b.array[i]) {
			return LARGER;
		}
		else if (a.array[i] < b.array[i]) {
			return SMALLER;
		}
	}
	while (i != 0);

	return EQUAL;
}


/* Signed compare bn */
int bignum_cmp_signed(bn_t a, bn_t b)
{
	int i = BN_ARRAY_SIZE;
	do {
		i -= 1; /* Decrement first, to start with last array element */
		if ((DTYPE_SIGNED)a.array[i] > (DTYPE_SIGNED)b.array[i]) {
			return LARGER;
		}
		else if ((DTYPE_SIGNED)a.array[i] < (DTYPE_SIGNED)b.array[i]) {
			return SMALLER;
		}
	}
	while (i != 0);

	return EQUAL;
}


/* Unsigned compare bn */
int bignum_cmp_unsigned(bn_t a, bn_t b)
{
	return bignum_cmp(a, b);
}


/* Return 1 if a == b else 0 */
int bignum_is_equal(bn_t a, bn_t b)
{
	int ret;
	ret = bignum_cmp_unsigned(a, b);
	if (ret == EQUAL)
		return 1;
	else
		return 0;
}


/* Return 1 if a <u b else 0 */
int bignum_is_inf_unsigned(bn_t a, bn_t b)
{
	int ret;
	ret = bignum_cmp_unsigned(a, b);
	if (ret == SMALLER)
		return 1;
	else
		return 0;
}


/* Return 1 if a <=u b else 0 */
int bignum_is_inf_equal_unsigned(bn_t a, bn_t b)
{
	int ret;
	ret = bignum_cmp_unsigned(a, b);
	if (ret == EQUAL || ret == SMALLER)
		return 1;
	else
		return 0;
}


/* Return 1 if a <s b else 0 */
int bignum_is_inf_signed(bn_t a, bn_t b)
{
	int ret;
	ret = bignum_cmp_signed(a, b);
	if (ret == SMALLER)
		return 1;
	else
		return 0;
}


/* Return 1 if a <=s b else 0 */
int bignum_is_inf_equal_signed(bn_t a, bn_t b)
{
	int ret;
	ret = bignum_cmp_signed(a, b);
	if (ret == EQUAL || ret == SMALLER)
		return 1;
	else
		return 0;
}


int bignum_is_zero(bn_t n)
{
	//require(n, "n is null");

	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		if (n.array[i]) {
			return 0;
		}
	}

	return 1;
}



bn_t bignum_assign(bn_t src)
{
	//require(dst, "dst is null");
	//require(src, "src is null");
	bn_t dst;

	int i;
	for (i = 0; i < BN_ARRAY_SIZE; ++i) {
		dst.array[i] = src.array[i];
	}

	return dst;
}


bn_t bignum_mask(bn_t src, int bits)
{
	bn_t dst;
	bn_t mask;

	mask = bignum_from_int(0);
	mask = bignum_dec(mask);
	mask = bignum_rshift(mask, BN_BIT_SIZE - bits);
	dst = bignum_and(src, mask);
	return dst;
}

/* Private / Static functions. */
static bn_t _rshift_word(bn_t a, int nwords)
{
	/* Naive method: */
	//require(a, "a is null");
	int i;

	require(nwords >= 0, "no negative shifts");

	if (nwords >= BN_ARRAY_SIZE) {
		for (i = 0; i < BN_ARRAY_SIZE; ++i) {
			a.array[i] = 0;
		}
		return a;
	}

	for (i = 0; i < BN_ARRAY_SIZE - nwords; ++i) {
		a.array[i] = a.array[i + nwords];
	}

	for (; i < BN_ARRAY_SIZE; ++i) {
		a.array[i] = 0;
	}

	return a;
}


static bn_t _lshift_word(bn_t a, int nwords)
{
	//require(a, "a is null");
	require(nwords >= 0, "no negative shifts");

	int i;

	if (nwords >= BN_ARRAY_SIZE) {
		for (i = 0; i < BN_ARRAY_SIZE; ++i) {
			a.array[i] = 0;
		}
		return a;
	}

	/* Shift whole words */
	for (i = (BN_ARRAY_SIZE - 1); i >= nwords; --i) {
		a.array[i] = a.array[i - nwords];
	}
	/* Zero pad shifted words. */
	for (; i >= 0; --i) {
		a.array[i] = 0;
	}

	return a;
}


static bn_t _lshift_one_bit(bn_t a)
{
	//require(a, "a is null");

	int i;
	for (i = (BN_ARRAY_SIZE - 1); i > 0; --i) {
		a.array[i] = (a.array[i] << 1) | (a.array[i - 1] >> ((8 * WORD_SIZE) - 1));
	}
	a.array[0] <<= 1;

	return a;
}


static bn_t _rshift_one_bit(bn_t a)
{
	//require(a, "a is null");

	int i;
	for (i = 0; i < (BN_ARRAY_SIZE - 1); ++i) {
		a.array[i] = (a.array[i] >> 1) | (a.array[i + 1] << ((8 * WORD_SIZE) - 1));
	}
	a.array[BN_ARRAY_SIZE - 1] >>= 1;

	return a;
}


bn_t bignum_rol(bn_t a, int size, int nbits)
{
	bn_t c;

	c = bignum_or(
		      bignum_lshift(a, nbits),
		      bignum_rshift(a, size - nbits)
		      );
	c = bignum_mask(c, size);
	return c;
}


bn_t bignum_ror(bn_t a, int size, int nbits)
{
	bn_t c;

	c = bignum_or(
		      bignum_rshift(a, nbits),
		      bignum_lshift(a, size - nbits)
		      );
	c = bignum_mask(c, size);
	return c;
}


int bignum_getbit(bn_t a, int pos)
{
	int d_pos, bit_pos;

	require(pos < BN_BIT_SIZE, "size must be below bignum max size");

	d_pos = pos / (sizeof(DTYPE) * 8);
	bit_pos = pos % (sizeof(DTYPE) * 8);
	return !!(a.array[d_pos] & (1 << bit_pos));

}



/*
 * Count leading zeros - count the number of zero starting at the most
 * significant bit
 *
 * Example:
 * - cntleadzeros(size=32, src=2): 30
 * - cntleadzeros(size=32, src=0): 32
 */
int bignum_cntleadzeros(bn_t n, int size)
{
	int i;

	require(size, "size must be greater than 0");
	require(size <= BN_BIT_SIZE, "size must be below bignum max size");

	for (i = 0; i < size; i++) {
		if (bignum_getbit(n, size - i - 1))
			break;
	}

	return i;
}



/*
 * Count trailing zeros - count the number of zero starting at the least
 * significant bit
 *
 * Example:
 * - cnttrailzeros(size=32, src=2): 1
 * - cnttrailzeros(size=32, src=0): 32
 */
int bignum_cnttrailzeros(bn_t n, int size)
{
	int i;

	require(size, "size must be greater than 0");
	require(size <= BN_BIT_SIZE, "size must be below bignum max size");

	for (i = 0; i < size; i++) {
		if (bignum_getbit(n, i))
			break;
	}

	return i;
}




bn_t bignum_sdiv(bn_t a, bn_t b, int size)
{
	require(size, "size must be greater than 0");
	require(size <= BN_BIT_SIZE, "size must be below bignum max size");

	int a_sign, b_sign;
	bn_t c;

	a_sign = bignum_getbit(a, size - 1);
	b_sign = bignum_getbit(b, size - 1);

	if (a_sign) {
		/* neg a */
		printf("a neg\n");
		a = bignum_sub(bignum_from_int(0), a);
		a = bignum_mask(a, size - 1);
	}

	if (b_sign) {
		/* neg b */
		printf("b neg\n");
		b = bignum_sub(bignum_from_int(0), b);
		b = bignum_mask(b, size - 1);
	}

	c = bignum_udiv(a, b);
	if (a_sign ^ b_sign) {
		c = bignum_sub(bignum_from_int(0), c);
	}

	c = bignum_mask(c, size);
	return c;
}



bn_t bignum_smod(bn_t a, bn_t b, int size)
{
	require(size, "size must be greater than 0");
	require(size <= BN_BIT_SIZE, "size must be below bignum max size");

	bn_t c;

	c = bignum_sdiv(a, b, size);
	c = bignum_mul(c, b);
	c = bignum_sub(a, c);
	c = bignum_mask(c, size);
	return c;
}
