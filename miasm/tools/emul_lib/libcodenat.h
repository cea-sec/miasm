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


#if __BYTE_ORDER == __BIG_ENDIAN
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
#else
#define Endian16_Swap(value) (value)

#define Endian32_Swap(value) (value)

#define Endian64_Swap(value) (value)
#endif




LIST_HEAD(memory_page_list_head, memory_page_node);
LIST_HEAD(code_bloc_list_head, code_bloc_node);

LIST_HEAD(memory_breakpoint_info_head, memory_breakpoint_info);


#define BREAKPOINT_READ 1
#define BREAKPOINT_WRITE 2


typedef struct {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int esi;
	unsigned int edi;
	unsigned int esp;
	unsigned int ebp;
	unsigned int eip;

	unsigned int zf;
	unsigned int nf;
	unsigned int pf;
	unsigned int of;
	unsigned int cf;
	unsigned int af;
	unsigned int df;

	unsigned int eax_new;
	unsigned int ebx_new;
	unsigned int ecx_new;
	unsigned int edx_new;
	unsigned int esi_new;
	unsigned int edi_new;
	unsigned int esp_new;
	unsigned int ebp_new;
	unsigned int eip_new;

	unsigned int zf_new;
	unsigned int nf_new;
	unsigned int pf_new;
	unsigned int of_new;
	unsigned int cf_new;
	unsigned int af_new;
	unsigned int df_new;

	unsigned int tf;
	unsigned int i_f;
	unsigned int iopl_f;
	unsigned int nt;
	unsigned int rf;
	unsigned int vm;
	unsigned int ac;
	unsigned int vif;
	unsigned int vip;
	unsigned int i_d;
	unsigned int tf_new;
	unsigned int i_f_new;
	unsigned int iopl_f_new;
	unsigned int nt_new;
	unsigned int rf_new;
	unsigned int vm_new;
	unsigned int ac_new;
	unsigned int vif_new;
	unsigned int vip_new;
	unsigned int  i_d_new;

	unsigned int my_tick;

	unsigned int cond;

	unsigned int vm_exception_flags;
	unsigned int vm_exception_flags_new;
	unsigned int vm_last_write_ad;
	unsigned int vm_last_write_size ;



	double float_st0;
	double float_st1;
	double float_st2;
	double float_st3;
	double float_st4;
	double float_st5;
	double float_st6;
	double float_st7;

	double float_st0_new;
	double float_st1_new;
	double float_st2_new;
	double float_st3_new;
	double float_st4_new;
	double float_st5_new;
	double float_st6_new;
	double float_st7_new;

	unsigned int float_c0;
	unsigned int float_c1;
	unsigned int float_c2;
	unsigned int float_c3;

	unsigned int float_c0_new;
	unsigned int float_c1_new;
	unsigned int float_c2_new;
	unsigned int float_c3_new;

	unsigned int float_stack_ptr;
	unsigned int float_stack_ptr_new;

	unsigned int reg_float_control;
	unsigned int reg_float_control_new;

	unsigned int reg_float_eip;
	unsigned int reg_float_eip_new;
	unsigned int reg_float_cs;
	unsigned int reg_float_cs_new;
	unsigned int reg_float_address;
	unsigned int reg_float_address_new;
	unsigned int reg_float_ds;
	unsigned int reg_float_ds_new;


	unsigned int tsc1;
	unsigned int tsc2;

	unsigned int tsc1_new;
	unsigned int tsc2_new;


	uint16_t es;
	uint16_t cs;
	uint16_t ss;
	uint16_t ds;
	uint16_t fs;
	uint16_t gs;

	uint16_t es_new;
	uint16_t cs_new;
	uint16_t ss_new;
	uint16_t ds_new;
	uint16_t fs_new;
	uint16_t gs_new;

	unsigned int cr0;
	unsigned int cr0_new;

	unsigned int cr3;
	unsigned int cr3_new;

	uint8_t pfmem08_0;
	uint8_t pfmem08_1;
	uint8_t pfmem08_2;
	uint8_t pfmem08_3;
	uint8_t pfmem08_4;
	uint8_t pfmem08_5;
	uint8_t pfmem08_6;
	uint8_t pfmem08_7;

	uint16_t pfmem16_0;
	uint16_t pfmem16_1;
	uint16_t pfmem16_2;
	uint16_t pfmem16_3;
	uint16_t pfmem16_4;
	uint16_t pfmem16_5;
	uint16_t pfmem16_6;
	uint16_t pfmem16_7;

	uint32_t pfmem32_0;
	uint32_t pfmem32_1;
	uint32_t pfmem32_2;
	uint32_t pfmem32_3;
	uint32_t pfmem32_4;
	uint32_t pfmem32_5;
	uint32_t pfmem32_6;
	uint32_t pfmem32_7;

	uint64_t pfmem64_0;
	uint64_t pfmem64_1;
	uint64_t pfmem64_2;
	uint64_t pfmem64_3;
	uint64_t pfmem64_4;
	uint64_t pfmem64_5;
	uint64_t pfmem64_6;
	uint64_t pfmem64_7;

	uint32_t segm_base[0x10000];

}vm_cpu_t;


extern vm_cpu_t vmcpu;

typedef struct _memory_page{
}memory_page;

struct memory_page_node {
	uint64_t ad;
	unsigned int size;
	unsigned int access;
	void* ad_hp;
	//memory_page *mp;
	LIST_ENTRY(memory_page_node)   next;
};



struct code_bloc_node {
	uint64_t ad_start;
	uint64_t ad_stop;
	uint64_t ad_code;
	LIST_ENTRY(code_bloc_node)   next;
};


struct memory_breakpoint_info {
	uint64_t ad;
	unsigned int access;
	LIST_ENTRY(memory_breakpoint_info)   next;
};


#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4


//memory_page* create_memory_page(uint64_t ad, unsigned int size);

//PyObject* _vm_get_exception(unsigned int xcpt);

// interrupt with eip update after instr
#define EXCEPT_CODE_AUTOMOD (1<<0)
#define EXCEPT_SOFT_BP (1<<1)

#define EXCEPT_BREAKPOINT_INTERN (1<<2)

#define EXCEPT_NUM_UDPT_EIP (1<<5)
// interrupt with eip at instr
#define EXCEPT_UNK_MEM_AD (1<<6)
#define EXCEPT_THROW_SEH (1<<7)
#define EXCEPT_UNK_EIP (1<<8)
#define EXCEPT_ACCESS_VIOL (1<<9)
#define EXCEPT_INT_DIV_BY_ZERO (1<<10)
#define EXCEPT_PRIV_INSN (1<<11)
#define EXCEPT_ILLEGAL_INSN (1<<12)

void dump_gpregs(void);
int is_mem_mapped(uint64_t ad);
uint64_t get_mem_base_addr(uint64_t addr, uint64_t *addr_base);
void MEM_WRITE(unsigned int my_size, uint64_t addr, unsigned int src);
unsigned int MEM_LOOKUP(unsigned int my_size, uint64_t addr);


void MEM_WRITE_08(uint64_t addr, unsigned char src);
void MEM_WRITE_16(uint64_t addr, unsigned short src);
void MEM_WRITE_32(uint64_t addr, unsigned int src);
void MEM_WRITE_64(uint64_t addr, uint64_t src);

void MEM_WRITE_08_SEGM(uint16_t segm, uint64_t addr, unsigned char src);
void MEM_WRITE_16_SEGM(uint16_t segm, uint64_t addr, unsigned short src);
void MEM_WRITE_32_SEGM(uint16_t segm, uint64_t addr, unsigned int src);
void MEM_WRITE_64_SEGM(uint16_t segm, uint64_t addr, uint64_t src);


unsigned char MEM_LOOKUP_08(uint64_t addr);
unsigned short MEM_LOOKUP_16(uint64_t addr);
unsigned int MEM_LOOKUP_32(uint64_t addr);
uint64_t MEM_LOOKUP_64(uint64_t addr);


unsigned char MEM_LOOKUP_08_SEGM(uint16_t segm, uint64_t addr);
unsigned short MEM_LOOKUP_16_SEGM(uint16_t segm, uint64_t addr);
unsigned int MEM_LOOKUP_32_SEGM(uint16_t segm, uint64_t addr);
uint64_t MEM_LOOKUP_64_SEGM(uint16_t segm, uint64_t addr);




void MEM_WRITE_08_PASSTHROUGH(uint64_t addr, unsigned char src);
void MEM_WRITE_16_PASSTHROUGH(uint64_t addr, unsigned short src);
void MEM_WRITE_32_PASSTHROUGH(uint64_t addr, unsigned int src);
void MEM_WRITE_64_PASSTHROUGH(uint64_t addr, uint64_t src);
unsigned char MEM_LOOKUP_08_PASSTHROUGH(uint64_t addr);
unsigned short MEM_LOOKUP_16_PASSTHROUGH(uint64_t addr);
unsigned int MEM_LOOKUP_32_PASSTHROUGH(uint64_t addr);
uint64_t MEM_LOOKUP_64_PASSTHROUGH(uint64_t addr);


inline unsigned int parity(unsigned int a);
unsigned int my_imul08(unsigned int a, unsigned int b);

void vm_throw(unsigned long flags);
int shift_right_arith(unsigned int size, int a, unsigned int b);
unsigned int shift_right_logic(unsigned int size, unsigned int a, unsigned int b);
int shift_left_logic(unsigned int size, unsigned int a, unsigned int b);
/*
int shift_left_logic_08(unsigned int a, unsigned int b);
int shift_left_logic_16(unsigned int a, unsigned int b);
int shift_left_logic_32(unsigned int a, unsigned int b);
*/
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


unsigned int div_op(unsigned int size, unsigned int a, unsigned int b, unsigned int c);
unsigned int rem_op(unsigned int size, unsigned int a, unsigned int b, unsigned int c);
int rot_left(unsigned int size, unsigned int a, unsigned int b);
int rot_right(unsigned int size, unsigned int a, unsigned int b);
int rcl_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf);
int rcl_cf_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf);
void _vm_init_regs(void);


//PyObject* _vm_push_uint32_t(PyObject *item);
//PyObject* _vm_pop_uint32_t(void);
////PyObject* _vm_put_str(PyObject *item);
//PyObject* _vm_set_mem(PyObject *item, PyObject *item_str);
//PyObject* _vm_set_mem_access(PyObject *addr, PyObject *access);
//PyObject* _vm_get_str(PyObject *item, PyObject *item_len);
//PyObject* _vm_add_memory_page(PyObject *item, PyObject *access, PyObject *item_str);
//PyObject* _vm_add_code_bloc(PyObject *item1, PyObject *item2);//, PyObject *item3);
//PyObject* _call_pyfunc_from_globals(char* funcname);
//PyObject* _call_pyfunc_from_eip(void);
//
//PyObject* call_pyfunc_from_globals(char* funcname);
//
//PyObject* _vm_get_gpreg(void);

typedef struct _reg_dict{
    char* name;
    unsigned int* ptr;
} reg_dict;

typedef struct _reg_segm_dict{
    char* name;
    uint16_t* ptr;
} reg_segm_dict;

typedef struct _reg_float_dict{
    char* name;
    void* ptr;
} reg_float_dict;

extern reg_dict gpreg_dict[];
//PyObject* _vm_set_gpreg(PyObject *dict);


void hexdump(char* m, unsigned int l);

struct code_bloc_node * create_code_bloc_node(uint64_t ad_start, uint64_t ad_stop);
void add_code_bloc(struct code_bloc_node* cbp);

struct memory_page_node * create_memory_page_node(uint64_t ad, unsigned int size, unsigned int access);//memory_page* mp);
void init_memory_page_pool(void);
void init_code_bloc_pool(void);
void reset_memory_page_pool(void);
void reset_code_bloc_pool(void);
void dump_code_bloc_pool(void);


void init_memory_breakpoint(void);
void reset_memory_breakpoint(void);
void add_memory_breakpoint(uint64_t ad, unsigned int access);
void remove_memory_breakpoint(uint64_t ad, unsigned int access);


void add_memory_page(struct memory_page_node* mpn);

void dump_memory_page_pool(void);
void dump_memory_breakpoint_pool(void);
//PyObject* _vm_get_all_memory(void);




/********************************************/

//PyObject* _vm_get_cpu_state(void);
//PyObject*  _vm_set_cpu_state(PyObject * s_cpustate);


//void memory_page_write(unsigned int my_size, uint64_t ad, unsigned int src);
//unsigned int memory_page_read(unsigned int my_size, uint64_t ad);
unsigned int get_memory_page_max_address(void);
unsigned int get_memory_page_max_user_address(void);


int is_mpn_in_tab(struct memory_page_node* mpn_a);


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
struct memory_page_node * get_memory_page_from_address(uint64_t ad);
void func_malloc_memory_page(void);
void func_free_memory_page(void);
void func_virtualalloc_memory_page(void);
void func_virtualfree_memory_page(void);
void func_loadlib_fake(void);
void func_getproc_fake(void);


//PyObject* _vm_exec_bloc(PyObject* my_eip, PyObject* known_blocs);

unsigned int cpuid(unsigned int a, unsigned int reg_num);
double int2double(unsigned int m);
//PyObject* _vm_exec_blocs(PyObject* my_eip);

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
unsigned int fcom_c0(double a, double b);
unsigned int fcom_c1(double a, double b);
unsigned int fcom_c2(double a, double b);
unsigned int fcom_c3(double a, double b);



double mem_32_to_double(unsigned int m);
double mem_64_to_double(uint64_t m);
double int_32_to_double(unsigned int m);
double int_64_to_double(uint64_t m);
int double_to_int_32(double d);
double fadd(double a, double b);
unsigned int double_to_mem_32(double d);
uint64_t double_to_mem_64(double d);


#define shift_right_arith_08(a, b)\
	((((char)(a)) >> ((int)(b)))&0xff)
#define shift_right_arith_16(a, b)\
	((((short)(a)) >> ((int)(b)))&0xffff)
#define shift_right_arith_32(a, b)\
	((((int)(a)) >> ((int)(b)))&0xffffffff)


#define shift_right_logic_08(a, b)\
	((((unsigned char)(a)) >> ((unsigned int)(b)))&0xff)
#define shift_right_logic_16(a, b)\
	((((unsigned short)(a)) >> ((unsigned int)(b)))&0xffff)
#define shift_right_logic_32(a, b)\
	((((unsigned int)(a)) >> ((unsigned int)(b)))&0xffffffff)


#define shift_left_logic_08(a, b)\
	(((a)<<(b))&0xff)
#define shift_left_logic_16(a, b)\
	(((a)<<(b))&0xffff)
#define shift_left_logic_32(a, b)\
	(((a)<<(b))&0xffffffff)

#endif
