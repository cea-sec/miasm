#ifndef OP_SEMANTICS_H
#define OP_SEMANTICS_H

#include <stdint.h>

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#define _MIASM_IMPORT __declspec(dllimport)
#else
#define _MIASM_EXPORT
#define _MIASM_IMPORT
#endif

#define CC_P 1
#ifdef PARITY_IMPORT
_MIASM_IMPORT extern const uint8_t parity_table[256];
#else
_MIASM_EXPORT extern const uint8_t parity_table[256];
#endif
#define parity(a) parity_table[(a) & 0xFF]


_MIASM_EXPORT uint16_t bcdadd_16(uint16_t a, uint16_t b);
_MIASM_EXPORT uint16_t bcdadd_cf_16(uint16_t a, uint16_t b);


_MIASM_EXPORT unsigned int my_imul08(unsigned int a, unsigned int b);
_MIASM_EXPORT unsigned int mul_lo_op(unsigned int size, unsigned int a, unsigned int b);
_MIASM_EXPORT unsigned int mul_hi_op(unsigned int size, unsigned int a, unsigned int b);
_MIASM_EXPORT unsigned int imul_lo_op_08(char a, char b);
_MIASM_EXPORT unsigned int imul_lo_op_16(short a, short b);
_MIASM_EXPORT unsigned int imul_lo_op_32(int a, int b);
_MIASM_EXPORT int imul_hi_op_08(char a, char b);
_MIASM_EXPORT int imul_hi_op_16(short a, short b);
_MIASM_EXPORT int imul_hi_op_32(int a, int b);


_MIASM_EXPORT unsigned int umul16_lo(unsigned short a, unsigned short b);
_MIASM_EXPORT unsigned int umul16_hi(unsigned short a, unsigned short b);


_MIASM_EXPORT uint64_t rot_left(uint64_t size, uint64_t a, uint64_t b);
_MIASM_EXPORT uint64_t rot_right(uint64_t size, uint64_t a, uint64_t b);

_MIASM_EXPORT uint64_t cntleadzeros(uint64_t size, uint64_t src);
_MIASM_EXPORT unsigned int cnttrailzeros(uint64_t size, uint64_t src);

#define UDIV(sizeA)						\
	uint ## sizeA ## _t udiv ## sizeA (uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
	{								\
		uint ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a/b;						\
		return r;						\
	}


#define UMOD(sizeA)						\
	uint ## sizeA ## _t umod ## sizeA (uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
	{								\
		uint ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a%b;						\
		return r;						\
	}


#define SDIV(sizeA)						\
	int ## sizeA ## _t sdiv ## sizeA (int ## sizeA ## _t a, int ## sizeA ## _t b) \
	{								\
		int ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a/b;						\
		return r;						\
	}


#define SMOD(sizeA)						\
	int ## sizeA ## _t smod ## sizeA (int ## sizeA ## _t a, int ## sizeA ## _t b) \
	{								\
		int ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a%b;						\
		return r;						\
	}

_MIASM_EXPORT uint64_t udiv64(uint64_t a, uint64_t b);
_MIASM_EXPORT uint64_t umod64(uint64_t a, uint64_t b);
_MIASM_EXPORT int64_t sdiv64(int64_t a, int64_t b);
_MIASM_EXPORT int64_t smod64(int64_t a, int64_t b);

_MIASM_EXPORT uint32_t udiv32(uint32_t a, uint32_t b);
_MIASM_EXPORT uint32_t umod32(uint32_t a, uint32_t b);
_MIASM_EXPORT int32_t sdiv32(int32_t a, int32_t b);
_MIASM_EXPORT int32_t smod32(int32_t a, int32_t b);

_MIASM_EXPORT uint16_t udiv16(uint16_t a, uint16_t b);
_MIASM_EXPORT uint16_t umod16(uint16_t a, uint16_t b);
_MIASM_EXPORT int16_t sdiv16(int16_t a, int16_t b);
_MIASM_EXPORT int16_t smod16(int16_t a, int16_t b);

_MIASM_EXPORT uint8_t udiv8(uint8_t a, uint8_t b);
_MIASM_EXPORT uint8_t umod8(uint8_t a, uint8_t b);
_MIASM_EXPORT int8_t sdiv8(int8_t a, int8_t b);
_MIASM_EXPORT int8_t smod8(int8_t a, int8_t b);

_MIASM_EXPORT unsigned int x86_cpuid(unsigned int a, unsigned int reg_num);

_MIASM_EXPORT uint32_t fpu_fadd32(uint32_t a, uint32_t b);
_MIASM_EXPORT uint64_t fpu_fadd64(uint64_t a, uint64_t b);
_MIASM_EXPORT uint32_t fpu_fsub32(uint32_t a, uint32_t b);
_MIASM_EXPORT uint64_t fpu_fsub64(uint64_t a, uint64_t b);
_MIASM_EXPORT uint32_t fpu_fmul32(uint32_t a, uint32_t b);
_MIASM_EXPORT uint64_t fpu_fmul64(uint64_t a, uint64_t b);
_MIASM_EXPORT uint32_t fpu_fdiv32(uint32_t a, uint32_t b);
_MIASM_EXPORT uint64_t fpu_fdiv64(uint64_t a, uint64_t b);
_MIASM_EXPORT double fpu_ftan(double a);
_MIASM_EXPORT double fpu_frndint(double a);
_MIASM_EXPORT double fpu_fsin(double a);
_MIASM_EXPORT double fpu_fcos(double a);
_MIASM_EXPORT double fpu_fscale(double a, double b);
_MIASM_EXPORT double fpu_f2xm1(double a);
_MIASM_EXPORT uint32_t fpu_fsqrt32(uint32_t a);
_MIASM_EXPORT uint64_t fpu_fsqrt64(uint64_t a);
_MIASM_EXPORT uint64_t fpu_fabs64(uint64_t a);
_MIASM_EXPORT uint64_t fpu_fprem64(uint64_t a, uint64_t b);
_MIASM_EXPORT double fpu_fchs(double a);
_MIASM_EXPORT double fpu_fyl2x(double a, double b);
_MIASM_EXPORT double fpu_fpatan(double a, double b);
_MIASM_EXPORT unsigned int fpu_fcom_c0(double a, double b);
_MIASM_EXPORT unsigned int fpu_fcom_c1(double a, double b);
_MIASM_EXPORT unsigned int fpu_fcom_c2(double a, double b);
_MIASM_EXPORT unsigned int fpu_fcom_c3(double a, double b);

_MIASM_EXPORT uint64_t sint_to_fp_64(int64_t a);
_MIASM_EXPORT uint32_t sint_to_fp_32(int32_t a);
_MIASM_EXPORT int32_t fp32_to_sint32(uint32_t a);
_MIASM_EXPORT int64_t fp64_to_sint64(uint64_t a);
_MIASM_EXPORT int32_t fp64_to_sint32(uint64_t a);
_MIASM_EXPORT uint32_t fp64_to_fp32(uint64_t a);
_MIASM_EXPORT uint64_t fp32_to_fp64(uint32_t a);
_MIASM_EXPORT uint32_t fpround_towardszero_fp32(uint32_t a);
_MIASM_EXPORT uint64_t fpround_towardszero_fp64(uint64_t a);

#define SHIFT_RIGHT_ARITH(size, value, shift)				\
	((uint ## size ## _t)((((uint64_t) (shift)) > ((size) - 1))?	\
			      (((int ## size ## _t) (value)) < 0 ? -1 : 0) : \
			      (((int ## size ## _t) (value)) >> (shift))))

#define SHIFT_RIGHT_LOGIC(size, value, shift)				\
	((uint ## size ## _t)((((uint64_t) (shift)) > ((size) - 1))?	\
			      0 :					\
			      (((uint ## size ## _t) (value)) >> (shift))))

#define SHIFT_LEFT_LOGIC(size, value, shift)		\
	((uint ## size ## _t)((((uint64_t) (shift)) > ((size) - 1))?	\
			      0 :					\
			      (((uint ## size ## _t) (value)) << (shift))))

#endif
