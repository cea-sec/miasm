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
//#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <stdint.h>
#include <inttypes.h>
#include <math.h>

#include "queue.h"
#include "libcodenat.h"





struct memory_page_list_head memory_page_pool;
struct code_bloc_list_head code_bloc_pool;

struct memory_breakpoint_info_head memory_breakpoint_pool;

vm_cpu_t vmcpu;

/****************memory manager**************/

unsigned int min_page_ad = 0x22000000;

extern unsigned int *code_addr_tab;


unsigned int code_bloc_pool_ad_min;
unsigned int code_bloc_pool_ad_max;

#define MAX_MEMORY_PAGE_POOL_TAB 0x100000
#define MEMORY_PAGE_POOL_MASK_BIT 12
#define PAGE_SIZE (1<<MEMORY_PAGE_POOL_MASK_BIT)
struct memory_page_node *memory_page_pool_tab[MAX_MEMORY_PAGE_POOL_TAB];


#define MIN(a,b)  (((a)<(b))?(a):(b))
#define MAX(a,b)  (((a)>(b))?(a):(b))


//#define DEBUG_MIASM_AUTOMOD_CODE








int is_mem_mapped(uint64_t ad)
{
	struct memory_page_node * mpn;

	mpn = memory_page_pool_tab[ad>>MEMORY_PAGE_POOL_MASK_BIT];
	if ( mpn && (mpn->ad <= ad) && (ad < mpn->ad + mpn->size))
		return 1;
	return 0;
}


/* return the address base of the memory page
   containing addr
*/
uint64_t get_mem_base_addr(uint64_t ad, uint64_t *addr_base)
{
	struct memory_page_node * mpn;

	mpn = memory_page_pool_tab[ad>>MEMORY_PAGE_POOL_MASK_BIT];
	if ( mpn && (mpn->ad <= ad) && (ad < mpn->ad + mpn->size)){
		*addr_base = mpn->ad;
		return 1;
	}
	return 0;
}


void dump_gpregs(void)
{
	printf("eip %.8X eax %.8X ebx %.8X ecx %.8X edx %.8X\n",
	       vmcpu.eip, vmcpu.eax, vmcpu.ebx, vmcpu.ecx, vmcpu.edx);
	printf("esi %.8X edi %.8X esp %.8X ebp %.8X\nmy_tick %X\n",
	       vmcpu.esi, vmcpu.edi, vmcpu.esp, vmcpu.ebp,
	       vmcpu.my_tick);
}

struct memory_page_node * get_memory_page_from_address(uint64_t ad)
{
	struct memory_page_node * mpn;
#if 1
	mpn = memory_page_pool_tab[ad>>MEMORY_PAGE_POOL_MASK_BIT];
	if ( mpn && (mpn->ad <= ad) && (ad < mpn->ad + mpn->size))
		return mpn;

	fprintf(stderr, "WARNING: address 0x%"PRIX64" is not mapped in virtual memory:\n", ad);
	//dump_memory_page_pool();
	//dump_gpregs();
	//exit(-1);
	vmcpu.vm_exception_flags |= EXCEPT_ACCESS_VIOL;

	return NULL;
#else

	//printf("search for page ad: %X\n", ad);
	LIST_FOREACH(mpn, &memory_page_pool, next){
		if ((mpn->ad <= ad) && (ad < mpn->ad + mpn->size))
			return mpn;
	}
	fprintf(stderr, "address %"PRIX64" is not mapped in virtual memory \n", ad);
	dump_memory_page_pool();
	dump_gpregs();
	//exit(-1);
	vmcpu.vm_exception_flags |= EXCEPT_ACCESS_VIOL;
	return NULL;
#endif
}




static inline uint64_t memory_page_read(unsigned int my_size, uint64_t ad)
{
	struct memory_page_node * mpn;
	unsigned char * addr;
	uint64_t ret = 0;
	struct memory_breakpoint_info * b;


	mpn = get_memory_page_from_address(ad);
	if (!mpn)
		return 0;

	if ((mpn->access & PAGE_READ) == 0){
		fprintf(stderr, "access to non readable page!! %"PRIX64"\n", ad);
		vmcpu.vm_exception_flags |= EXCEPT_ACCESS_VIOL;
		return 0;
	}

	/* check read breakpoint*/
	LIST_FOREACH(b, &memory_breakpoint_pool, next){
		if ((b->access & BREAKPOINT_READ) == 0)
			continue;
		if (b->ad == ad)
			vmcpu.vm_exception_flags |= EXCEPT_BREAKPOINT_INTERN;
	}


	addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];

	/* read fits in a page */
	if (ad - mpn->ad + my_size/8 <= mpn->size){
		switch(my_size){
		case 8:
			ret = *((unsigned char*)addr)&0xFF;
			break;
		case 16:
			ret = *((unsigned short*)addr)&0xFFFF;
			ret = Endian16_Swap(ret);
			break;
		case 32:
			ret = *((unsigned int*)addr)&0xFFFFFFFF;
			ret = Endian32_Swap(ret);
			break;
		case 64:
			ret = *((uint64_t*)addr)&0xFFFFFFFFFFFFFFFFULL;
			ret = Endian64_Swap(ret);
			break;
		default:
			exit(0);
			break;
		}
	}
	/* read is multiple page wide */
	else{
		unsigned int new_size = my_size;
		int index = 0;
		fprintf(stderr, "read multiple page! %"PRIX64" %d\n", ad, new_size);
		dump_memory_page_pool();
		while (new_size){
			mpn = get_memory_page_from_address(ad);
			if (!mpn)
				return 0;
			addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];
			ret |= (*((unsigned char*)addr)&0xFF)<<(index);
			index +=8;
			new_size -= 8;
			ad ++;
		}
		switch(my_size){
		case 8:
			ret = ret;
			break;
		case 16:
			ret = Endian16_Swap(ret);
			break;
		case 32:
			ret = Endian32_Swap(ret);
			break;
		case 64:
			ret = Endian64_Swap(ret);
			break;
		default:
			exit(0);
			break;
		}
	}
	return ret;
}

static inline void memory_page_write(unsigned int my_size,
				     uint64_t ad, uint64_t src)
{
	struct memory_page_node * mpn;
	unsigned char * addr;
	struct memory_breakpoint_info * b;

	mpn = get_memory_page_from_address(ad);
	if (!mpn)
		return;

	if ((mpn->access & PAGE_WRITE) == 0){
		fprintf(stderr, "access to non writable page!! %"PRIX64"\n", ad);
		vmcpu.vm_exception_flags |= EXCEPT_ACCESS_VIOL;
		return ;
	}

	/* check read breakpoint*/
	LIST_FOREACH(b, &memory_breakpoint_pool, next){
		if ((b->access & BREAKPOINT_WRITE) == 0)
			continue;
		if (b->ad == ad)
			vmcpu.vm_exception_flags |= EXCEPT_BREAKPOINT_INTERN;
	}

	addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];

	/* write fits in a page */
	if (ad - mpn->ad + my_size/8 <= mpn->size){
		switch(my_size){
		case 8:
			*((unsigned char*)addr) = src&0xFF;
			break;
		case 16:
			src = Endian16_Swap(src);
			*((unsigned short*)addr) = src&0xFFFF;
			break;
		case 32:
			src = Endian32_Swap(src);
			*((unsigned int*)addr) = src&0xFFFFFFFF;
			break;
		case 64:
			src = Endian64_Swap(src);
			*((uint64_t*)addr) = src&0xFFFFFFFFFFFFFFFFULL;
			break;
		default:
			exit(0);
			break;
		}
	}
	/* write is multiple page wide */
	else{
		fprintf(stderr, "write multiple page! %"PRIX64" %d\n", ad, my_size);
		dump_memory_page_pool();
		switch(my_size){

		case 8:
			src = src;
			break;
		case 16:
			src = Endian16_Swap(src);
			break;
		case 32:
			src = Endian32_Swap(src);
			break;
		case 64:
			src = Endian64_Swap(src);
			break;
		default:
			exit(0);
			break;
		}
		while (my_size){
			mpn = get_memory_page_from_address(ad);
			if (!mpn)
				return;

			addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];
			*((unsigned char*)addr) = src&0xFF;
			my_size -= 8;
			src >>=8;
			ad ++;
		}
	}
}



inline void check_write_code_bloc(unsigned int my_size, uint64_t addr)
{
	struct code_bloc_node * cbp;
	vmcpu.vm_last_write_ad = addr;
	vmcpu.vm_last_write_size = my_size;

	//if(vmcpu.my_tick> my_tick)
	//	printf("M_WRITE %2d %.8X %.8X\n", my_size, addr, src);
	if (!(addr + my_size/8 <= code_bloc_pool_ad_min ||
	      addr >=code_bloc_pool_ad_max)){
		LIST_FOREACH(cbp, &code_bloc_pool, next){
			if ((cbp->ad_start <= addr + my_size/8) &&
			    (addr < cbp->ad_stop)){
#ifdef DEBUG_MIASM_AUTOMOD_CODE
				fprintf(stderr, "self modifying code %"PRIX64" %.8X",
				       addr, my_size);
				fprintf(stderr, " from approx %X\n", vmcpu.eip);
#endif
				vmcpu.vm_exception_flags |= EXCEPT_CODE_AUTOMOD;
				break;
			}
		}
	}
}

void MEM_WRITE(unsigned int my_size, uint64_t addr, unsigned int src)
{
	struct code_bloc_node * cbp;

	vmcpu.vm_last_write_ad = addr;
	vmcpu.vm_last_write_size = my_size;

	//if(vmcpu.my_tick> my_tick)
	//	printf("M_WRITE %2d %.8X %.8X\n", my_size, addr, src);
	if (!(addr + my_size/8 <= code_bloc_pool_ad_min ||
	      addr >=code_bloc_pool_ad_max)){
		LIST_FOREACH(cbp, &code_bloc_pool, next){
			if ((cbp->ad_start <= addr + my_size/8) &&
			    (addr < cbp->ad_stop)){
#ifdef DEBUG_MIASM_AUTOMOD_CODE
				fprintf(stderr, "self modifying code %"PRIX64" %.8X",
				       addr, my_size);
				fprintf(stderr, " from approx %X\n", vmcpu.eip);
#endif
				vmcpu.vm_exception_flags |= EXCEPT_CODE_AUTOMOD;
				break;
			}
		}
	}

	memory_page_write(my_size, addr, src);
}

void MEM_WRITE_08(uint64_t addr, unsigned char src)
{
	check_write_code_bloc(8, addr);
	memory_page_write(8, addr, src);
}

void MEM_WRITE_08_SEGM(uint16_t segm, uint64_t addr, unsigned char src)
{
	check_write_code_bloc(8, addr + vmcpu.segm_base[segm]);
	memory_page_write(8, addr + vmcpu.segm_base[segm], src);
}

void MEM_WRITE_16(uint64_t addr, unsigned short src)
{
	check_write_code_bloc(16, addr);
	memory_page_write(16, addr, src);
}

void MEM_WRITE_16_SEGM(uint16_t segm, uint64_t addr, unsigned short src)
{
	check_write_code_bloc(16, addr + vmcpu.segm_base[segm]);
	memory_page_write(16, addr + vmcpu.segm_base[segm], src);
}

void MEM_WRITE_32(uint64_t addr, unsigned int src)
{
	check_write_code_bloc(32, addr);
	memory_page_write(32, addr, src);
}

void MEM_WRITE_32_SEGM(uint16_t segm, uint64_t addr, unsigned int src)
{
	check_write_code_bloc(32, addr + vmcpu.segm_base[segm]);
	memory_page_write(32, addr + vmcpu.segm_base[segm], src);
}

void MEM_WRITE_64(uint64_t addr, uint64_t src)
{
	check_write_code_bloc(64, addr);
	memory_page_write(64, addr, src);
}

void MEM_WRITE_64_SEGM(uint16_t segm, uint64_t addr, uint64_t src)
{
	check_write_code_bloc(64, addr + vmcpu.segm_base[segm]);
	memory_page_write(64, addr + vmcpu.segm_base[segm], src);
}


unsigned int MEM_LOOKUP(unsigned int my_size, uint64_t addr)
{
    unsigned int ret;
    ret = memory_page_read(my_size, addr);
    return ret;
}

unsigned char MEM_LOOKUP_08(uint64_t addr)
{
    unsigned char ret;
    ret = memory_page_read(8, addr);
    return ret;
}

unsigned char MEM_LOOKUP_08_SEGM(uint16_t segm, uint64_t addr)
{
    unsigned char ret;
    ret = memory_page_read(8, addr + vmcpu.segm_base[segm]);
    return ret;
}

unsigned short MEM_LOOKUP_16(uint64_t addr)
{
    unsigned short ret;
    ret = memory_page_read(16, addr);
    return ret;
}

unsigned short MEM_LOOKUP_16_SEGM(uint16_t segm, uint64_t addr)
{
    unsigned short ret;
    ret = memory_page_read(16, addr + vmcpu.segm_base[segm]);
    return ret;
}

unsigned int MEM_LOOKUP_32(uint64_t addr)
{
    unsigned int ret;
    ret = memory_page_read(32, addr);
    return ret;
}

unsigned int MEM_LOOKUP_32_SEGM(uint16_t segm, uint64_t addr)
{
    unsigned int ret;
    ret = memory_page_read(32, addr + vmcpu.segm_base[segm]);
    return ret;
}

uint64_t MEM_LOOKUP_64(uint64_t addr)
{
    uint64_t ret;
    ret = memory_page_read(64, addr);
    return ret;
}

uint64_t MEM_LOOKUP_64_SEGM(uint16_t segm, uint64_t addr)
{
    uint64_t ret;
    ret = memory_page_read(64, addr + vmcpu.segm_base[segm]);
    return ret;
}

void vm_throw(unsigned long flags)
{
	vmcpu.vm_exception_flags |= flags;
}

inline unsigned int parity(unsigned int a)
{
    unsigned int tmp, cpt;

    tmp = a&0xFF;
    cpt = 1;
    while (tmp!=0){
	    cpt^=tmp&1;
	    tmp>>=1;
    }
    return cpt;
}


int shift_right_arith(unsigned int size, int a, unsigned int b)
{
    int i32_a;
    short i16_a;
    char i8_a;
    switch(size){
	    case 8:
		    i8_a = a;
		    return (i8_a >> b)&0xff;
	    case 16:
		    i16_a = a;
		    return (i16_a >> b)&0xffff;
	    case 32:
		    i32_a = a;
		    return (i32_a >> b)&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in shift %d\n", size);
		    exit(0);
    }
}
/*
int shift_right_arith_08(int a, unsigned int b)
{
	char i8_a;
	i8_a = a;
	return (i8_a >> b)&0xff;
}

int shift_right_arith_16(int a, unsigned int b)
{
	short i16_a;
	i16_a = a;
	return (i16_a >> b)&0xffff;
}

int shift_right_arith_32(int a, unsigned int b)
{
	int i32_a;
	i32_a = a;
	return (i32_a >> b)&0xffffffff;
}
*/
unsigned int shift_right_logic(unsigned int size,
			       unsigned int a, unsigned int b)
{
    unsigned int u32_a;
    unsigned short u16_a;
    unsigned char u8_a;
    switch(size){
	    case 8:
		    u8_a = a;
		    return (u8_a >> b)&0xff;
	    case 16:
		    u16_a = a;
		    return (u16_a >> b)&0xffff;
	    case 32:
		    u32_a = a;
		    return (u32_a >> b)&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in shift %d\n", size);
		    exit(0);
    }
}
/*
int shift_right_logic_08(unsigned int a, unsigned int b)
{
	unsigned char u8_a;
	u8_a = a;
	return (u8_a >> b)&0xff;
}

int shift_right_logic_16(unsigned int a, unsigned int b)
{
	unsigned short u16_a;
	u16_a = a;
	return (u16_a >> b)&0xffff;
}

int shift_right_logic_32(unsigned int a, unsigned int b)
{
	unsigned int u32_a;
	u32_a = a;
	return (u32_a >> b)&0xffffffff;
}
*/
int shift_left_logic(unsigned int size, unsigned int a, unsigned int b)
{
    switch(size){
	    case 8:
		    return (a<<b)&0xff;
	    case 16:
		    return (a<<b)&0xffff;
	    case 32:
		    return (a<<b)&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in shift %d\n", size);
		    exit(0);
    }
}
/*
int shift_left_logic_O8(unsigned int a, unsigned int b)
{
	return (a<<b)&0xff;
}

int shift_left_logic_16(unsigned int a, unsigned int b)
{
	return (a<<b)&0xffff;
}

int shift_left_logic_32(unsigned int a, unsigned int b)
{
	return (a<<b)&0xffffffff;
}
*/

unsigned int mul_lo_op(unsigned int size, unsigned int a, unsigned int b)
{
	unsigned int mask;

	switch (size) {
		case 8: mask = 0xff; break;
		case 16: mask = 0xffff; break;
		case 32: mask = 0xffffffff; break;
		default: fprintf(stderr, "inv size in mul %d\n", size); exit(0);
	}

	a &= mask;
	b &= mask;
	return ((int64_t)a * (int64_t) b) & mask;
}

unsigned int mul_hi_op(unsigned int size, unsigned int a, unsigned int b)
{
	uint64_t res = 0;
	unsigned int mask;

	switch (size) {
		case 8: mask = 0xff; break;
		case 16: mask = 0xffff; break;
		case 32: mask = 0xffffffff; break;
		default: fprintf(stderr, "inv size in mul %d\n", size); exit(0);
	}

	a &= mask;
	b &= mask;
	res = ((uint64_t)a * (uint64_t)b);
	return (res >> 32) & mask;
}


unsigned int imul_lo_op_08(char a, char b)
{
	return a*b;
}

unsigned int imul_lo_op_16(short a, short b)
{
	return a*b;
}

unsigned int imul_lo_op_32(int a, int b)
{
	return a*b;
}

int imul_hi_op_08(char a, char b)
{
	int64_t res = 0;
	res = a*b;
	return res>>8;
}

int imul_hi_op_16(short a, short b)
{
	int64_t res = 0;
	res = a*b;
	return res>>16;
}

int imul_hi_op_32(int a, int b)
{
	int64_t res = 0;
	res = a*b;
	return res>>32;
}

unsigned int umul16_lo(unsigned short a, unsigned short b)
{
	return (a*b) & 0xffff;
}

unsigned int umul16_hi(unsigned short a, unsigned short b)
{
	uint32_t c;
	c = a*b;
	return (c>>16) & 0xffff;
}




unsigned int div_op(unsigned int size, unsigned int a, unsigned int b, unsigned int c)
{
    int64_t num;
    if (c == 0)
    {
	    vmcpu.vm_exception_flags |= EXCEPT_INT_DIV_BY_ZERO;
	    return 0;
    }
    num = ((int64_t)a << size) + b;
    num/=(int64_t)c;
    return num;
}

unsigned int rem_op(unsigned int size, unsigned int a, unsigned int b, unsigned int c)
{
    int64_t num;

    if (c == 0)
    {
	    vmcpu.vm_exception_flags |= EXCEPT_INT_DIV_BY_ZERO;
	    return 0;
    }

    num = ((int64_t)a << size) + b;
    num = (int64_t)num-c*(num/c);
    return num;
}


int rot_left(unsigned int size, unsigned int a, unsigned int b)
{
    unsigned int tmp;

    b = b&0x1F;
    b %= size;
    switch(size){
	    case 8:
		    tmp = (a << b) | ((a&0xFF) >> (size-b));
		    return tmp&0xff;
	    case 16:
		    tmp = (a << b) | ((a&0xFFFF) >> (size-b));
		    return tmp&0xffff;
	    case 32:
		    tmp = (a << b) | ((a&0xFFFFFFFF) >> (size-b));
		    return tmp&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in rotleft %d\n", size);
		    exit(0);
    }
}

int rot_right(unsigned int size, unsigned int a, unsigned int b)
{
    unsigned int tmp;

    b = b&0x1F;
    b %= size;
    switch(size){
	    case 8:
		    tmp = ((a&0xFF) >> b) | (a << (size-b));
		    return tmp&0xff;
	    case 16:
		    tmp = ((a&0xFFFF) >> b) | (a << (size-b));
		    return tmp&0xffff;
	    case 32:
		    tmp = ((a&0xFFFFFFFF) >> b) | (a << (size-b));
		    return tmp&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in rotleft %d\n", size);
		    exit(0);
    }
}


int rcl_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
    uint64_t tmp;

    tmp = (cf << size) | a;

    size++;
    b %= size;

    switch(size){
	    case 8+1:
		    tmp = (tmp << b) | ((tmp&0x1FF) >> (size-b));
		    return tmp&0xff;
	    case 16+1:
		    tmp = (tmp << b) | ((tmp&0x1FFFF) >> (size-b));
		    return tmp&0xffff;
	    case 32+1:
		    tmp = (tmp << b) | ((tmp&0x1FFFFFFFFULL) >> (size-b));
		    return tmp&0xffffffff;
	    default:
		    fprintf(stderr, "inv size in rclleft %d\n", size);
		    exit(0);
    }
}

int rcr_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
	return rcl_rez_op(size, a, size+1-b, cf);

}


int rcl_cf_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
    uint64_t tmp;

    tmp = (cf<< size) | a;

    size++;
    b %= size;

    switch(size){
	    case 8+1:
		    tmp = (tmp << b) | ((tmp&0x1FF) >> (size-b));
		    return (tmp>>8)&1;
	    case 16+1:
		    tmp = (tmp << b) | ((tmp&0x1FFFF) >> (size-b));
		    return (tmp>>16)&1;
	    case 32+1:
		    tmp = (tmp << b) | ((tmp&0x1FFFFFFFFULL) >> (size-b));
		    return (tmp>>32)&1;
	    default:
		    fprintf(stderr, "inv size in rclleft %d\n", size);
		    exit(0);
    }
}

int rcr_cf_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
	return rcl_cf_op(size, a, size+1-b, cf);
}
unsigned int my_bsr(unsigned int a, unsigned int b)
{
	int i;

	for (i=31; i>=0; i--){
		if (b & (1<<i))
			return i;
	}
	return a;
}

unsigned int my_bsf(unsigned int a, unsigned int b)
{
	int i;

	for (i=0; i<32; i++){
		if (b & (1<<i))
			return i;
	}
	return a;
}


unsigned int my_imul08(unsigned int a, unsigned int b)
{
	char a08, b08;
	short a16;

	a08 = a&0xFF;
	b08 = b&0xFF;
	a16 = a08*b08;
	return (int)a16;
}



unsigned int cpuid(unsigned int a, unsigned int reg_num)
{
	if (reg_num >3){
		fprintf(stderr, "not implemented cpuid reg %x\n", reg_num);
		exit(-1);
	}

	if (a == 0){
		switch(reg_num){
		case 0:
			return 0xa;
		case 1:
			return 0x756E6547;
		case 2:
			return 0x6C65746E;
		case 3:
			return 0x49656E69;
		}
	}

	else if (a == 1){
		switch(reg_num){
		case 0:
			//return 0x000006FB;
			return 0x00020652;
		case 1:
			//return 0x02040800;
			return 0x00000800;
		case 2:
			//return 0x0004E3BD;
			return 0x00000209;
		case 3:
			//return 0xBFEBFBFF;
			return 0x078bf9ff;
		}
	}
	else{
		fprintf(stderr, "WARNING not implemented cpuid index %X!\n", a);
		//exit(-1);
	}
	return 0;
}

#define DEBUG_MIASM_DOUBLE

double mem_32_to_double(unsigned int m)
{
	float f;
	double d;

	f = *((float*)&m);
	d = f;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%d %e\n", m, d);
#endif
	return d;
}


double mem_64_to_double(uint64_t m)
{
	double d;
	d = *((double*)&m);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%"PRId64" %e\n", m, d);
#endif
	return d;
}

double int_16_to_double(unsigned int m)
{
	double d;

	d = (double)(m&0xffff);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%d %e\n", m, d);
#endif
	return d;
}

double int_32_to_double(unsigned int m)
{
	double d;

	d = (double)m;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%d %e\n", m, d);
#endif
	return d;
}

double int_64_to_double(uint64_t m)
{
	double d;

	d = (double)m;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%"PRId64" %e\n", m, d);
#endif
	return d;
}

int double_to_int_32(double d)
{
	int i;

	i = (int)d;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %d\n", d, i);
#endif
	return i;
}

double fadd(double a, double b)
{
	double c;
	c = a + b;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e %e\n", a, b, c);
#endif
	return c;
}

double fsub(double a, double b)
{
	double c;
	c = a - b;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e %e\n", a, b, c);
#endif
	return c;
}

double fmul(double a, double b)
{
	double c;
	c = a * b;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e %e\n", a, b, c);
#endif
	return c;
}

double fdiv(double a, double b)
{
	double c;
	c = a / b;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e %e\n", a, b, c);
#endif
	return c;
}

double ftan(double a)
{
	double b;
	b = tan(a);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}

double frndint(double a)
{
	int64_t b;
	double c;
	b = (int64_t)a;
	c = (double)b;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, c);
#endif
	return c;
}

double fsin(double a)
{
	double b;
	b = sin(a);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}

double fcos(double a)
{
	double b;
	b = cos(a);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}


double fscale(double a, double b)
{
	double c;
	c = a * exp2(trunc(b));
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e %e\n", a, b, c);
#endif
	return c;
}

double f2xm1(double a)
{
	double b;
	b = exp2(a)-1;
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}

double fsqrt(double a)
{
	double b;
	b = sqrt(a);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}

double fabs(double a)
{
	double b;
	b = abs(a);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%e %e\n", a, b);
#endif
	return b;
}



unsigned int fcom_c0(double a, double b)
{
	if (a>=b)
		return 0;
	return 1;
}
unsigned int fcom_c1(double a, double b)
{
	//XXX
	return 0;
}
unsigned int fcom_c2(double a, double b)
{
	return 0;
}
unsigned int fcom_c3(double a, double b)
{
	if (a==b)
		return 1;
	return 0;
}


unsigned int double_to_mem_32(double d)
{
	unsigned int m;
	float f;
	f = d;
	m = *((unsigned int*)&f);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%d %e\n", m, d);
#endif
	return m;
}

uint64_t double_to_mem_64(double d)
{
	uint64_t m;
	m = *((uint64_t*)&d);
#ifdef DEBUG_MIASM_DOUBLE
	printf("%"PRId64" %e\n", m, d);
#endif
	return m;
}

struct memory_page_node * create_memory_page_node(uint64_t ad, unsigned int size, unsigned int access)
{
	struct memory_page_node * mpn;
	void* p;

	mpn = malloc(sizeof(*mpn));
	if (!mpn){
		fprintf(stderr, "cannot alloc mpn\n");
		return NULL;
	}
	p = malloc(size);
	if (!p){
		fprintf(stderr, "cannot alloc %d\n", size);
		return NULL;
	}
	mpn->ad = ad;
	mpn->size = size;
	mpn->access = access;
	mpn->ad_hp = p;

	return mpn;
}


struct code_bloc_node * create_code_bloc_node(uint64_t ad_start, uint64_t ad_stop)
{
	struct code_bloc_node * cbp;

	cbp = malloc(sizeof(*cbp));
	if (!cbp){
		fprintf(stderr, "cannot alloc cbp\n");
		exit(-1);
	}

	cbp->ad_start = ad_start;
	cbp->ad_stop = ad_stop;

	return cbp;
}


void add_code_bloc(struct code_bloc_node* cbp)
{
	LIST_INSERT_HEAD(&code_bloc_pool, cbp, next);
	if (code_bloc_pool_ad_min> cbp->ad_start)
		code_bloc_pool_ad_min = cbp->ad_start;
	if (code_bloc_pool_ad_max< cbp->ad_stop)
		code_bloc_pool_ad_max = cbp->ad_stop;
}

void dump_code_bloc_pool(void)
{
	struct code_bloc_node * cbp;

	LIST_FOREACH(cbp, &code_bloc_pool, next){
		printf("ad start %"PRIX64" ad_stop %"PRIX64"\n",
		       cbp->ad_start,
		       cbp->ad_stop);
	}
}


void init_memory_page_pool(void)
{
	unsigned int i;
	LIST_INIT(&memory_page_pool);
	for (i=0;i<MAX_MEMORY_PAGE_POOL_TAB; i++)
		memory_page_pool_tab[i] = NULL;
}

void init_code_bloc_pool(void)
{
	LIST_INIT(&code_bloc_pool);
	code_bloc_pool_ad_min = 0xffffffff;
	code_bloc_pool_ad_max = 0;
}

void init_memory_breakpoint(void)
{
	LIST_INIT(&memory_breakpoint_pool);
}


void reset_memory_page_pool(void)
{
	struct memory_page_node * mpn;
	unsigned int i;

	while (!LIST_EMPTY(&memory_page_pool)) {
		mpn = LIST_FIRST(&memory_page_pool);
		LIST_REMOVE(mpn, next);
		free(mpn->ad_hp);
		free(mpn);
	}
	for (i=0;i<MAX_MEMORY_PAGE_POOL_TAB; i++)
		memory_page_pool_tab[i] = NULL;

}


void reset_code_bloc_pool(void)
{
	struct code_bloc_node * cbp;


	while (!LIST_EMPTY(&code_bloc_pool)) {
		cbp = LIST_FIRST(&code_bloc_pool);
		LIST_REMOVE(cbp, next);
		free(cbp);
	}
	code_bloc_pool_ad_min = 0xffffffff;
	code_bloc_pool_ad_max = 0;
}


void reset_memory_breakpoint(void)
{
	struct memory_breakpoint_info * mpn;

	while (!LIST_EMPTY(&memory_breakpoint_pool)) {
		mpn = LIST_FIRST(&memory_breakpoint_pool);
		LIST_REMOVE(mpn, next);
		free(mpn);
	}

}


int is_mpn_in_tab(struct memory_page_node* mpn_a)
{
	unsigned int i;
	for (i=mpn_a->ad >> MEMORY_PAGE_POOL_MASK_BIT;
	     i<(mpn_a->ad + mpn_a->size + PAGE_SIZE - 1)>>MEMORY_PAGE_POOL_MASK_BIT;
	     i++){
		if (memory_page_pool_tab[i] !=NULL){
			return 1;
		}
	}

	return 0;
}

void insert_mpn_in_tab(struct memory_page_node* mpn_a)
{
	unsigned int i;
	for (i=mpn_a->ad >> MEMORY_PAGE_POOL_MASK_BIT;
	     i<(mpn_a->ad + mpn_a->size + PAGE_SIZE - 1)>>MEMORY_PAGE_POOL_MASK_BIT;
	     i++){
		if (memory_page_pool_tab[i] !=NULL){
			fprintf(stderr, "known page in tab\n");
			exit(1);
		}
		memory_page_pool_tab[i] = mpn_a;
	}

}

void add_memory_page(struct memory_page_node* mpn_a)
{
	struct memory_page_node * mpn;
	struct memory_page_node * lmpn;

	if (LIST_EMPTY(&memory_page_pool)){
		LIST_INSERT_HEAD(&memory_page_pool, mpn_a, next);
		insert_mpn_in_tab(mpn_a);
		return;
	}
	LIST_FOREACH(mpn, &memory_page_pool, next){
		lmpn = mpn;
		if (mpn->ad < mpn_a->ad)
			continue;
		LIST_INSERT_BEFORE(mpn, mpn_a, next);
		insert_mpn_in_tab(mpn_a);
		return;
	}
	LIST_INSERT_AFTER(lmpn, mpn_a, next);
	insert_mpn_in_tab(mpn_a);

}

void dump_memory_page_pool()
{
	struct memory_page_node * mpn;

	LIST_FOREACH(mpn, &memory_page_pool, next){
		printf("ad %"PRIX64" size %.8X %c%c%c hpad %p\n",
		       mpn->ad,
		       mpn->size,
		       mpn->access & PAGE_READ? 'R':'_',
		       mpn->access & PAGE_WRITE? 'W':'_',
		       mpn->access & PAGE_EXEC? 'X':'_',
		       mpn->ad_hp
		       );
	}
}

void dump_memory_breakpoint_pool(void)
{
	struct memory_breakpoint_info * mpn;

	LIST_FOREACH(mpn, &memory_breakpoint_pool, next){
		printf("ad %"PRIX64" access %.8X\n",
		       mpn->ad,
		       mpn->access
		       );
	}
}


void add_memory_breakpoint(uint64_t ad, unsigned int access)
{
	struct memory_breakpoint_info * mpn_a;
	mpn_a = malloc(sizeof(*mpn_a));
	if (!mpn_a) {
		printf("cannot alloc\n");
		exit(0);
	}
	mpn_a->ad = ad;
	mpn_a->access = access;

	LIST_INSERT_HEAD(&memory_breakpoint_pool, mpn_a, next);

}

void remove_memory_breakpoint(uint64_t ad, unsigned int access)
{
	struct memory_breakpoint_info * mpn;

	LIST_FOREACH(mpn, &memory_breakpoint_pool, next){
		if (mpn->ad == ad  && mpn->access == access)
			LIST_REMOVE(mpn, next);
	}

}





unsigned int get_memory_page_max_address(void)
{
	struct memory_page_node * mpn;
	uint64_t ad = 0;

	LIST_FOREACH(mpn, &memory_page_pool, next){
		if (ad < mpn->ad + mpn->size)
			ad = mpn->ad + mpn->size;
	}
	return ad;
}

unsigned int get_memory_page_max_user_address(void)
{
	struct memory_page_node * mpn;
	uint64_t ad = 0;

	LIST_FOREACH(mpn, &memory_page_pool, next){
		if (ad < mpn->ad + mpn->size &&
		    mpn->ad + mpn->size < 0x80000000)
			ad = mpn->ad + mpn->size;
	}
	return ad;
}


unsigned int get_memory_page_next(unsigned int n_ad)
{
	struct memory_page_node * mpn;
	uint64_t ad = 0;

	LIST_FOREACH(mpn, &memory_page_pool, next){
		if (mpn->ad < n_ad)
			continue;

		if (ad == 0 || mpn->ad <ad)
			ad = mpn->ad;
	}
	return ad;
}



unsigned int get_memory_page_from_min_ad(unsigned int size)
{
	struct memory_page_node * mpn;
	unsigned int c_ad ;
	unsigned int min_ad = min_page_ad;
	int end = 0;
	/* first, find free min ad */
	while (!end){
		end = 1;
		LIST_FOREACH(mpn, &memory_page_pool, next){
			c_ad = (mpn->ad + mpn->size+0x1000)&0xfffff000;
			if (c_ad <= min_ad)
				continue;
			if (mpn->ad <= min_ad){
				min_ad = c_ad;
				end = 0;
				break;
			}
			if (mpn->ad - min_ad < size){
				min_ad = c_ad;
				end = 0;
				break;
			}
		}
	}
	return min_ad;
 }




/********************************************/

void hexdump(char* m, unsigned int l)
{
  int i, j, last;
  last = 0;
  for (i=0;i<l;i++){
      if (!(i%0x10) && i){
      last = i;
      printf("    ");
      for (j=-0x10;j<0;j++){
	      if (isprint(m[i+j])){
		      printf("%c", m[i+j]);
	      }
	      else{
		      printf(".");
	      }
      }
      printf("\n");
      }
      printf("%.2X ", m[i]&0xFF);
  }
  l-=last;
  if (l){
    for (j=i;j<last+0x10;j++)
      printf("   ");
    printf("    ");
    for (j = 0;l;j++){
      if (isprint(m[last+j])){
	      printf("%c", m[last+j]);
      }
      else{
	      printf(".");
      }
      l--;
    }
  }
  printf("\n");

}





void _vm_init_regs()
{
	vmcpu.eax = vmcpu.ebx = vmcpu.ecx = vmcpu.edx = 0;
	vmcpu.esi = vmcpu.edi = vmcpu.esp = vmcpu.ebp = 0;
	vmcpu.zf = vmcpu.nf = vmcpu.pf = vmcpu.of = 0;
	vmcpu.cf = vmcpu.af = vmcpu.df = 0;
	vmcpu.eax_new = vmcpu.ebx_new = vmcpu.ecx_new = vmcpu.edx_new = 0;
	vmcpu.esi_new = vmcpu.edi_new = vmcpu.esp_new = vmcpu.ebp_new = 0;
	vmcpu.zf_new = vmcpu.nf_new = vmcpu.pf_new = vmcpu.of_new = 0;
	vmcpu.cf_new = vmcpu.af_new = vmcpu.df_new = 0;
	vmcpu.esp = 0;
	vmcpu.tsc1 = 0x22222222;
	vmcpu.tsc2 = 0x11111111;

	vmcpu.i_f = 1;
}



unsigned int _get_memory_page_max_address_py(void)
{
    unsigned int ret;
    ret = get_memory_page_max_address();
    return ret;
}

unsigned int _get_memory_page_max_user_address_py(void)
{
    unsigned int ret;
    ret = get_memory_page_max_user_address();
    return ret;
}

unsigned int _get_memory_page_from_min_ad_py(unsigned int size)
{
    unsigned int ret;
    ret = get_memory_page_from_min_ad(size);
    return ret;
}




//#include "libcodenat_interface.c"
