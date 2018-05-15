#ifndef OP_SEMANTICS_H
#define OP_SEMANTICS_H

#define CC_P 1
extern const uint8_t parity_table[256];
#define parity(a) parity_table[(a) & 0xFF]

unsigned int my_imul08(unsigned int a, unsigned int b);
unsigned int mul_lo_op(unsigned int size, unsigned int a, unsigned int b);
unsigned int mul_hi_op(unsigned int size, unsigned int a, unsigned int b);
unsigned int imul_lo_op_08(char a, char b);
unsigned int imul_lo_op_16(short a, short b);
unsigned int imul_lo_op_32(int a, int b);
int imul_hi_op_08(char a, char b);
int imul_hi_op_16(short a, short b);
int imul_hi_op_32(int a, int b);


unsigned int umul16_lo(unsigned short a, unsigned short b);
unsigned int umul16_hi(unsigned short a, unsigned short b);


uint64_t rot_left(uint64_t size, uint64_t a, uint64_t b);
uint64_t rot_right(uint64_t size, uint64_t a, uint64_t b);

unsigned int cntleadzeros(uint64_t size, uint64_t src);
unsigned int cnttrailzeros(uint64_t size, uint64_t src);

#define UDIV(sizeA)						\
	uint ## sizeA ## _t udiv ## sizeA (vm_cpu_t* vmcpu, uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
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
	uint ## sizeA ## _t umod ## sizeA (vm_cpu_t* vmcpu, uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
	{								\
		uint ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a%b;						\
		return r;						\
	}


#define IDIV(sizeA)						\
	int ## sizeA ## _t idiv ## sizeA (vm_cpu_t* vmcpu, int ## sizeA ## _t a, int ## sizeA ## _t b) \
	{								\
		int ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a/b;						\
		return r;						\
	}


#define IMOD(sizeA)						\
	int ## sizeA ## _t imod ## sizeA (vm_cpu_t* vmcpu, int ## sizeA ## _t a, int ## sizeA ## _t b) \
	{								\
		int ## sizeA ## _t r;					\
		if (b == 0) {						\
			fprintf(stderr, "Should not happen\n");		\
			exit(EXIT_FAILURE);				\
		}							\
		r = a%b;						\
		return r;						\
	}

unsigned int x86_cpuid(unsigned int a, unsigned int reg_num);
double int2double(unsigned int m);

double fpu_fadd(double a, double b);
double fpu_fsub(double a, double b);
double fpu_fmul(double a, double b);
double fpu_fdiv(double a, double b);
double fpu_ftan(double a);
double fpu_frndint(double a);
double fpu_fsin(double a);
double fpu_fcos(double a);
double fpu_fscale(double a, double b);
double fpu_f2xm1(double a);
double fpu_fsqrt(double a);
double fpu_fabs(double a);
double fpu_fprem(double a, double b);
double fpu_fchs(double a);
double fpu_fyl2x(double a, double b);
double fpu_fpatan(double a, double b);
unsigned int fpu_fprem_lsb(double a, double b);
unsigned int fpu_fcom_c0(double a, double b);
unsigned int fpu_fcom_c1(double a, double b);
unsigned int fpu_fcom_c2(double a, double b);
unsigned int fpu_fcom_c3(double a, double b);
unsigned int fpu_fxam_c0(double a);
unsigned int fpu_fxam_c1(double a);
unsigned int fpu_fxam_c2(double a);
unsigned int fpu_fxam_c3(double a);


double mem_32_to_double(unsigned int m);
double mem_64_to_double(uint64_t m);
double int_16_to_double(unsigned int m);
double int_32_to_double(unsigned int m);
double int_64_to_double(uint64_t m);
int16_t double_to_int_16(double d);
int32_t double_to_int_32(double d);
int64_t double_to_int_64(double d);
unsigned int double_to_mem_32(double d);
uint64_t double_to_mem_64(double d);


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
