/*
** Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License along
** with this program; if not, write to the Free Software Foundation, Inc.,
** 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifndef CODENAT_H
#define CODENAT_H

#ifdef __APPLE__
#define __BYTE_ORDER __BYTE_ORDER__
#define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#elif defined(__NetBSD__)
#define __BYTE_ORDER _BYTE_ORDER
#define __BIG_ENDIAN _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif

#define Endian16_Swap(value) \
      ((((uint16_t)((value) & 0x00FF)) << 8) | \
       (((uint16_t)((value) & 0xFF00)) >> 8))

#define Endian32_Swap(value) \
	((((uint32_t)((value) & 0x000000FF)) << 24) |	\
	 (((uint32_t)((value) & 0x0000FF00)) << 8) |	\
	 (((uint32_t)((value) & 0x00FF0000)) >> 8) |	\
	 (((uint32_t)((value) & 0xFF000000)) >> 24))

#define Endian64_Swap(value)					      \
	(((((uint64_t)value)<<56) & 0xFF00000000000000ULL)  |	      \
	 ((((uint64_t)value)<<40) & 0x00FF000000000000ULL)  |	      \
	 ((((uint64_t)value)<<24) & 0x0000FF0000000000ULL)  |	      \
	 ((((uint64_t)value)<< 8) & 0x000000FF00000000ULL)  |	      \
	 ((((uint64_t)value)>> 8) & 0x00000000FF000000ULL)  |	      \
	 ((((uint64_t)value)>>24) & 0x0000000000FF0000ULL)  |	      \
	 ((((uint64_t)value)>>40) & 0x000000000000FF00ULL)  |	      \
	 ((((uint64_t)value)>>56) & 0x00000000000000FFULL))




LIST_HEAD(code_bloc_list_head, code_bloc_node);
LIST_HEAD(memory_breakpoint_info_head, memory_breakpoint_info);


#define BREAKPOINT_READ 1
#define BREAKPOINT_WRITE 2

#define BREAK_SIGALARM 1<<5

#define MAX_MEMORY_PAGE_POOL_TAB 0x100000
#define MEMORY_PAGE_POOL_MASK_BIT 12
#define PAGE_SIZE (1<<MEMORY_PAGE_POOL_MASK_BIT)
#define VM_BIG_ENDIAN 1
#define VM_LITTLE_ENDIAN 2


struct memory_page_node {
	uint64_t ad;
	uint64_t size;
	uint64_t access;
	void* ad_hp;
	char* name;
};

struct memory_access {
	uint64_t start;
	uint64_t stop;
};

struct memory_access_list {
	struct memory_access *array;
	uint64_t allocated;
	uint64_t num;
};

typedef struct {
	int sex;
	struct code_bloc_list_head code_bloc_pool;
	struct memory_breakpoint_info_head memory_breakpoint_pool;

	int memory_pages_number;
	struct memory_page_node* memory_pages_array;

	uint64_t code_bloc_pool_ad_min;
	uint64_t code_bloc_pool_ad_max;

	uint64_t exception_flags;
	uint64_t exception_flags_new;
	PyObject *addr2obj;


	struct memory_access_list memory_r;
	struct memory_access_list memory_w;


	int write_num;

}vm_mngr_t;



typedef struct {
	PyObject *func;
}func_resolver;




//extern vm_mngr_t vmmngr;

struct code_bloc_node {
	uint64_t ad_start;
	uint64_t ad_stop;
	uint64_t ad_code;
	LIST_ENTRY(code_bloc_node)   next;
};


struct memory_breakpoint_info {
	uint64_t ad;
	uint64_t size;
	uint64_t access;
	LIST_ENTRY(memory_breakpoint_info)   next;
};



#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4

#define EXCEPT_DO_NOT_UPDATE_PC (1<<25)

// interrupt with eip update after instr
#define EXCEPT_CODE_AUTOMOD (1<<0)
#define EXCEPT_SOFT_BP (1<<1)
#define EXCEPT_INT_XX (1<<2)

#define EXCEPT_BREAKPOINT_INTERN (1<<10)

#define EXCEPT_NUM_UPDT_EIP (1<<11)
// interrupt with eip at instr
#define EXCEPT_UNK_MEM_AD ((1<<12) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_THROW_SEH ((1<<13) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_UNK_EIP ((1<<14) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_ACCESS_VIOL ((1<<14) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_INT_DIV_BY_ZERO ((1<<16) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_PRIV_INSN ((1<<17) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_ILLEGAL_INSN ((1<<18) | EXCEPT_DO_NOT_UPDATE_PC)
#define EXCEPT_UNK_MNEMO ((1<<19) | EXCEPT_DO_NOT_UPDATE_PC)


int is_mem_mapped(vm_mngr_t* vm_mngr, uint64_t ad);
uint64_t get_mem_base_addr(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t *addr_base);
unsigned int MEM_LOOKUP(vm_mngr_t* vm_mngr, unsigned int my_size, uint64_t addr);


void vm_MEM_WRITE_08(vm_mngr_t* vm_mngr, uint64_t addr, unsigned char src);
void vm_MEM_WRITE_16(vm_mngr_t* vm_mngr, uint64_t addr, unsigned short src);
void vm_MEM_WRITE_32(vm_mngr_t* vm_mngr, uint64_t addr, unsigned int src);
void vm_MEM_WRITE_64(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t src);


unsigned char vm_MEM_LOOKUP_08(vm_mngr_t* vm_mngr, uint64_t addr);
unsigned short vm_MEM_LOOKUP_16(vm_mngr_t* vm_mngr, uint64_t addr);
unsigned int vm_MEM_LOOKUP_32(vm_mngr_t* vm_mngr, uint64_t addr);
uint64_t vm_MEM_LOOKUP_64(vm_mngr_t* vm_mngr, uint64_t addr);


void MEM_WRITE_08_PASSTHROUGH(uint64_t addr, unsigned char src);
void MEM_WRITE_16_PASSTHROUGH(uint64_t addr, unsigned short src);
void MEM_WRITE_32_PASSTHROUGH(uint64_t addr, unsigned int src);
void MEM_WRITE_64_PASSTHROUGH(uint64_t addr, uint64_t src);
unsigned char MEM_LOOKUP_08_PASSTHROUGH(uint64_t addr);
unsigned short MEM_LOOKUP_16_PASSTHROUGH(uint64_t addr);
unsigned int MEM_LOOKUP_32_PASSTHROUGH(uint64_t addr);
uint64_t MEM_LOOKUP_64_PASSTHROUGH(uint64_t addr);

int vm_read_mem(vm_mngr_t* vm_mngr, uint64_t addr, char** buffer_ptr, uint64_t size);
int vm_write_mem(vm_mngr_t* vm_mngr, uint64_t addr, char *buffer, uint64_t size);

#define CC_P 1

extern const uint8_t parity_table[256];

uint8_t parity(uint64_t a);

unsigned int my_imul08(unsigned int a, unsigned int b);

int is_mapped(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size);
void vm_throw(vm_mngr_t* vm_mngr, unsigned long flags);
int shift_right_arith(unsigned int size, int a, unsigned int b);

uint64_t shift_right_logic(uint64_t size, uint64_t a, uint64_t b);
uint64_t shift_left_logic(uint64_t size, uint64_t a, uint64_t b);
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
unsigned int rcl_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf);
unsigned int rcr_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf);


#define UDIV(sizeA)						\
    uint ## sizeA ## _t udiv ## sizeA (vm_cpu_t* vmcpu, uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
	    {								\
	    uint ## sizeA ## _t r;						\
	    if (b == 0) {						\
		    vmcpu->exception_flags |= EXCEPT_INT_DIV_BY_ZERO;	\
		    return 0;						\
	    }								\
	    r = a/b;							\
	    return r;							\
	    }


#define UMOD(sizeA)						\
    uint ## sizeA ## _t umod ## sizeA (vm_cpu_t* vmcpu, uint ## sizeA ## _t a, uint ## sizeA ## _t b) \
	    {								\
	    uint ## sizeA ## _t r;						\
	    if (b == 0) {						\
		    vmcpu->exception_flags |= EXCEPT_INT_DIV_BY_ZERO;	\
		    return 0;						\
	    }								\
	    r = a%b;							\
	    return r;							\
	    }


#define IDIV(sizeA)						\
    int ## sizeA ## _t idiv ## sizeA (vm_cpu_t* vmcpu, int ## sizeA ## _t a, int ## sizeA ## _t b) \
	    {								\
	    int ## sizeA ## _t r;						\
	    if (b == 0) {						\
		    vmcpu->exception_flags |= EXCEPT_INT_DIV_BY_ZERO;	\
		    return 0;						\
	    }								\
	    r = a/b;							\
	    return r;							\
	    }


#define IMOD(sizeA)						\
    int ## sizeA ## _t imod ## sizeA (vm_cpu_t* vmcpu, int ## sizeA ## _t a, int ## sizeA ## _t b) \
	    {								\
	    int ## sizeA ## _t r;						\
	    if (b == 0) {						\
		    vmcpu->exception_flags |= EXCEPT_INT_DIV_BY_ZERO;	\
		    return 0;						\
	    }								\
	    r = a%b;							\
	    return r;							\
	    }


void memory_access_list_init(struct memory_access_list * access);
void memory_access_list_reset(struct memory_access_list * access);
void memory_access_list_add(struct memory_access_list * access, uint64_t start, uint64_t stop);


void hexdump(char* m, unsigned int l);

struct code_bloc_node * create_code_bloc_node(uint64_t ad_start, uint64_t ad_stop);
void add_code_bloc(vm_mngr_t* vm_mngr, struct code_bloc_node* cbp);

struct memory_page_node * create_memory_page_node(uint64_t ad, unsigned int size, unsigned int access, char* name);//memory_page* mp);
void init_memory_page_pool(vm_mngr_t* vm_mngr);
void init_code_bloc_pool(vm_mngr_t* vm_mngr);
void reset_memory_page_pool(vm_mngr_t* vm_mngr);
void reset_code_bloc_pool(vm_mngr_t* vm_mngr);
void dump_code_bloc_pool(vm_mngr_t* vm_mngr);
void add_memory_page(vm_mngr_t* vm_mngr, struct memory_page_node* mpn_a);


void init_memory_breakpoint(vm_mngr_t* vm_mngr);
void reset_memory_breakpoint(vm_mngr_t* vm_mngr);
void add_memory_breakpoint(vm_mngr_t* vm_mngr, uint64_t ad, uint64_t size, unsigned int access);
void remove_memory_breakpoint(vm_mngr_t* vm_mngr, uint64_t ad, unsigned int access);

void add_memory_page(vm_mngr_t* vm_mngr, struct memory_page_node* mpn);

void add_mem_read(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size);
void add_mem_write(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size);
void check_invalid_code_blocs(vm_mngr_t* vm_mngr);
void check_memory_breakpoint(vm_mngr_t* vm_mngr);
void reset_memory_access(vm_mngr_t* vm_mngr);
PyObject* get_memory_read(vm_mngr_t* vm_mngr);
PyObject* get_memory_write(vm_mngr_t* vm_mngr);


char* dump(vm_mngr_t* vm_mngr);
void dump_memory_breakpoint_pool(vm_mngr_t* vm_mngr);
PyObject* addr2BlocObj(vm_mngr_t* vm_mngr, uint64_t addr);




/********************************************/
unsigned int get_memory_page_max_address(void);
unsigned int get_memory_page_max_user_address(void);


int is_mpn_in_tab(vm_mngr_t* vm_mngr, struct memory_page_node* mpn_a);


void _func_free(void);
void _func_alloc(void);
unsigned int _get_memory_page_max_address_py(void);
unsigned int _get_memory_page_max_user_address_py(void);
unsigned int _get_memory_page_from_min_ad_py(unsigned int size);

void _func_malloc_memory_page(void);
void _func_free_memory_page(void);
void _func_virtualalloc_memory_page(void);
void _func_virtualfree_memory_page(void);
void _func_loadlib_fake(void);
void _func_getproc_fake(void);


void func_free(void);
void func_alloc(void);
unsigned int get_memory_page_max_address_py(void);
unsigned int get_memory_page_max_user_address_py(void);
unsigned int get_memory_page_from_min_ad_py(unsigned int size);
struct memory_page_node * get_memory_page_from_address(vm_mngr_t*, uint64_t ad, int raise_exception);
void func_malloc_memory_page(void);
void func_free_memory_page(void);
void func_virtualalloc_memory_page(void);
void func_virtualfree_memory_page(void);
void func_loadlib_fake(void);
void func_getproc_fake(void);


unsigned int cpuid(unsigned int a, unsigned int reg_num);
double int2double(unsigned int m);

double fadd(double a, double b);
double fsub(double a, double b);
double fmul(double a, double b);
double fdiv(double a, double b);
double ftan(double a);
double frndint(double a);
double fsin(double a);
double fcos(double a);
double fscale(double a, double b);
double f2xm1(double a);
double fsqrt(double a);
double fabs(double a);
double fprem(double a, double b);
double fchs(double a);
double fyl2x(double a, double b);
double fpatan(double a, double b);
unsigned int fprem_lsb(double a, double b);
unsigned int fcom_c0(double a, double b);
unsigned int fcom_c1(double a, double b);
unsigned int fcom_c2(double a, double b);
unsigned int fcom_c3(double a, double b);
unsigned int fxam_c0(double a);
unsigned int fxam_c1(double a);
unsigned int fxam_c2(double a);
unsigned int fxam_c3(double a);


double mem_32_to_double(unsigned int m);
double mem_64_to_double(uint64_t m);
double int_16_to_double(unsigned int m);
double int_32_to_double(unsigned int m);
double int_64_to_double(uint64_t m);
int16_t double_to_int_16(double d);
int32_t double_to_int_32(double d);
int64_t double_to_int_64(double d);
double fadd(double a, double b);
unsigned int double_to_mem_32(double d);
uint64_t double_to_mem_64(double d);

unsigned int access_segment(unsigned int d);
unsigned int access_segment_ok(unsigned int d);

unsigned int load_segment_limit(unsigned int d);
unsigned int load_segment_limit_ok(unsigned int d);

unsigned int load_tr_segment_selector(unsigned int d);
#define shift_right_arith_08(a, b)\
	((((char)(a)) >> ((int)(b)&0x1f))&0xff)
#define shift_right_arith_16(a, b)\
	((((short)(a)) >> ((int)(b)&0x1f))&0xffff)
#define shift_right_arith_32(a, b)\
	((((int)(a)) >> ((int)(b)&0x1f))&0xffffffff)
#define shift_right_arith_64(a, b)\
	((((int64_t)(a)) >> ((int64_t)(b)&0x3f))&0xffffffffffffffff)


#define shift_right_logic_08(a, b)\
	((((unsigned char)(a)) >> ((unsigned int)(b)&0x1f))&0xff)
#define shift_right_logic_16(a, b)\
	((((unsigned short)(a)) >> ((unsigned int)(b)&0x1f))&0xffff)
#define shift_right_logic_32(a, b)\
	((((unsigned int)(a)) >> ((unsigned int)(b)&0x1f))&0xffffffff)
#define shift_right_logic_64(a, b)\
	((((uint64_t)(a)) >> ((uint64_t)(b)&0x3f))&0xffffffffffffffff)

#define shift_left_logic_08(a, b)\
	(((a)<<((b)&0x1f))&0xff)
#define shift_left_logic_16(a, b)\
	(((a)<<((b)&0x1f))&0xffff)
#define shift_left_logic_32(a, b)\
	(((a)<<((b)&0x1f))&0xffffffff)
#define shift_left_logic_64(a, b)\
	(((a)<<((b)&0x3f))&0xffffffffffffffff)

#endif
