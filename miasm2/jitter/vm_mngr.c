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
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <stdint.h>
#include <inttypes.h>
#include <math.h>

#include "queue.h"
#include "vm_mngr.h"




/****************memory manager**************/




#define MIN(a,b)  (((a)<(b))?(a):(b))
#define MAX(a,b)  (((a)>(b))?(a):(b))


const uint8_t parity_table[256] = {
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    CC_P, 0, 0, CC_P, 0, CC_P, CC_P, 0,
    0, CC_P, CC_P, 0, CC_P, 0, 0, CC_P,
};

// #define DEBUG_MIASM_AUTOMOD_CODE

void memory_access_list_init(struct memory_access_list * access)
{
	access->array = NULL;
	access->allocated = 0;
	access->num = 0;
}

void memory_access_list_reset(struct memory_access_list * access)
{
	if (access->array) {
		free(access->array);
		access->array = NULL;
	}
	access->allocated = 0;
	access->num = 0;
}

void memory_access_list_add(struct memory_access_list * access, uint64_t start, uint64_t stop)
{
	if (access->num >= access->allocated) {
		if (access->allocated == 0)
			access->allocated = 1;
		else
			access->allocated *= 2;
		access->array = realloc(access->array, access->allocated * sizeof(struct memory_access));
	}
	access->array[access->num].start = start;
	access->array[access->num].stop = stop;
	access->num += 1;
}



uint16_t set_endian16(vm_mngr_t* vm_mngr, uint16_t val)
{
	if (vm_mngr->sex == __BYTE_ORDER)
		return val;
	else
		return Endian16_Swap(val);
}

uint32_t set_endian32(vm_mngr_t* vm_mngr, uint32_t val)
{
	if (vm_mngr->sex == __BYTE_ORDER)
		return val;
	else
		return Endian32_Swap(val);
}

uint64_t set_endian64(vm_mngr_t* vm_mngr, uint64_t val)
{
	if (vm_mngr->sex == __BYTE_ORDER)
		return val;
	else
		return Endian64_Swap(val);
}


void print_val(uint64_t base, uint64_t addr)
{
	uint64_t *ptr = (uint64_t *) (intptr_t) addr;
	fprintf(stderr, "addr 0x%"PRIX64" val 0x%"PRIX64"\n", addr-base, *ptr);
}

inline int midpoint(int imin, int imax)
{
	return (imin + imax) / 2;
}


int find_page_node(struct memory_page_node * array, uint64_t key, int imin, int imax)
{
	// continue searching while [imin,imax] is not empty
	while (imin <= imax) {
		// calculate the midpoint for roughly equal partition
		int imid = midpoint(imin, imax);
		if(array[imid].ad <= key && key < array[imid].ad + array[imid].size)
			// key found at index imid
			return imid;
		// determine which subarray to search
		else if (array[imid].ad < key)
			// change min index to search upper subarray
			imin = imid + 1;
		else
			// change max index to search lower subarray
			imax = imid - 1;
	}
	// key was not found
	return -1;
}

struct memory_page_node * get_memory_page_from_address(vm_mngr_t* vm_mngr, uint64_t ad, int raise_exception)
{
	struct memory_page_node * mpn;
	int i;

	i = find_page_node(vm_mngr->memory_pages_array,
			   ad,
			   0,
			   vm_mngr->memory_pages_number - 1);
	if (i >= 0) {
		mpn = &vm_mngr->memory_pages_array[i];
		if ((mpn->ad <= ad) && (ad < mpn->ad + mpn->size))
			return mpn;
	}
	if (raise_exception) {
		fprintf(stderr, "WARNING: address 0x%"PRIX64" is not mapped in virtual memory:\n", ad);
		vm_mngr->exception_flags |= EXCEPT_ACCESS_VIOL;
	}
	return NULL;
}




static uint64_t memory_page_read(vm_mngr_t* vm_mngr, unsigned int my_size, uint64_t ad)
{
	struct memory_page_node * mpn;
	unsigned char * addr;
	uint64_t ret = 0;
	struct memory_breakpoint_info * b;


	mpn = get_memory_page_from_address(vm_mngr, ad, 1);
	if (!mpn)
		return 0;

	if ((mpn->access & PAGE_READ) == 0){
		fprintf(stderr, "access to non readable page!! %"PRIX64"\n", ad);
		vm_mngr->exception_flags |= EXCEPT_ACCESS_VIOL;
		return 0;
	}

	/* check read breakpoint */
	LIST_FOREACH(b, &vm_mngr->memory_breakpoint_pool, next){
		if ((b->access & BREAKPOINT_READ) == 0)
			continue;
		if ((b->ad <= ad) && (ad < b->ad + b->size))
			vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_INTERN;
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
			ret = set_endian16(vm_mngr, ret);
			break;
		case 32:
			ret = *((unsigned int*)addr)&0xFFFFFFFF;
			ret = set_endian32(vm_mngr, ret);
			break;
		case 64:
			ret = *((uint64_t*)addr)&0xFFFFFFFFFFFFFFFFULL;
			ret = set_endian64(vm_mngr, ret);
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
		while (new_size){
			mpn = get_memory_page_from_address(vm_mngr, ad, 1);
			if (!mpn)
				return 0;
			addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];
			ret |= ((uint64_t)(*((unsigned char*)addr)&0xFF))<<(index);
			index +=8;
			new_size -= 8;
			ad ++;
		}
		switch(my_size){
		case 8:
			ret = ret;
			break;
		case 16:
			ret = set_endian16(vm_mngr, ret);
			break;
		case 32:
			ret = set_endian32(vm_mngr, ret);
			break;
		case 64:
			ret = set_endian64(vm_mngr, ret);
			break;
		default:
			exit(0);
			break;
		}
	}
	return ret;
}

static void memory_page_write(vm_mngr_t* vm_mngr, unsigned int my_size,
			      uint64_t ad, uint64_t src)
{
	struct memory_page_node * mpn;
	unsigned char * addr;
	struct memory_breakpoint_info * b;

	mpn = get_memory_page_from_address(vm_mngr, ad, 1);
	if (!mpn)
		return;

	if ((mpn->access & PAGE_WRITE) == 0){
		fprintf(stderr, "access to non writable page!! %"PRIX64"\n", ad);
		vm_mngr->exception_flags |= EXCEPT_ACCESS_VIOL;
		return ;
	}

	/* check read breakpoint*/
	LIST_FOREACH(b, &vm_mngr->memory_breakpoint_pool, next){
		if ((b->access & BREAKPOINT_WRITE) == 0)
			continue;
		if ((b->ad <= ad) && (ad < b->ad + b->size))
			vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_INTERN;
	}

	addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];

	/* write fits in a page */
	if (ad - mpn->ad + my_size/8 <= mpn->size){
		switch(my_size){
		case 8:
			*((unsigned char*)addr) = src&0xFF;
			break;
		case 16:
			src = set_endian16(vm_mngr, src);
			*((unsigned short*)addr) = src&0xFFFF;
			break;
		case 32:
			src = set_endian32(vm_mngr, src);
			*((unsigned int*)addr) = src&0xFFFFFFFF;
			break;
		case 64:
			src = set_endian64(vm_mngr, src);
			*((uint64_t*)addr) = src&0xFFFFFFFFFFFFFFFFULL;
			break;
		default:
			exit(0);
			break;
		}
	}
	/* write is multiple page wide */
	else{
		switch(my_size){

		case 8:
			src = src;
			break;
		case 16:
			src = set_endian16(vm_mngr, src);
			break;
		case 32:
			src = set_endian32(vm_mngr, src);
			break;
		case 64:
			src = set_endian64(vm_mngr, src);
			break;
		default:
			exit(0);
			break;
		}
		while (my_size){
			mpn = get_memory_page_from_address(vm_mngr, ad, 1);
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

/* TODO: Those functions have to be moved to a common operations file, with
 * parity, ...
 */

uint16_t bcdadd_16(uint16_t a, uint16_t b)
{
	int carry = 0;
	int i,j = 0;
	uint16_t res = 0;
	int nib_a, nib_b;
	for (i = 0; i < 16; i += 4) {
		nib_a = (a  >> i) & (0xF);
		nib_b = (b >> i) & (0xF);

		j = (carry + nib_a + nib_b);
		if (j >= 10) {
			carry = 1;
			j -= 10;
			j &=0xf;
		}
		else {
			carry = 0;
		}
		res += j << i;
	}
	return res;
}

uint16_t bcdadd_cf_16(uint16_t a, uint16_t b)
{
	int carry = 0;
	int i,j = 0;
	int nib_a, nib_b;
	for (i = 0; i < 16; i += 4) {
		nib_a = (a >> i) & (0xF);
		nib_b = (b >> i) & (0xF);

		j = (carry + nib_a + nib_b);
		if (j >= 10) {
			carry = 1;
			j -= 10;
			j &=0xf;
		}
		else {
			carry = 0;
		}
	}
	return carry;
}
// ##################

void dump_code_bloc(vm_mngr_t* vm_mngr)
{
	struct code_bloc_node * cbp;
	LIST_FOREACH(cbp, &vm_mngr->code_bloc_pool, next){
		fprintf(stderr, "%"PRIX64"%"PRIX64"\n", cbp->ad_start,  cbp->ad_stop);
	}

}

void add_range_to_list(struct memory_access_list * access, uint64_t addr1, uint64_t addr2)
{
	if (access->num > 0) {
		/* Check match on upper bound */
		 if (access->array[access->num-1].stop == addr1) {
			 access->array[access->num-1].stop = addr2;
			 return;
		 }

		/* Check match on lower bound */
		 if (access->array[0].start == addr2) {
			 access->array[0].start = addr1;
			 return;
		 }
	}

	/* No merge, add to the list */
	memory_access_list_add(access, addr1, addr2);
}


void add_mem_read(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size)
{
	add_range_to_list(&(vm_mngr->memory_r), addr, addr + size);
}

void add_mem_write(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size)
{
	add_range_to_list(&(vm_mngr->memory_w), addr, addr + size);
}

void check_invalid_code_blocs(vm_mngr_t* vm_mngr)
{
	int i;
	struct code_bloc_node * cbp;
	for (i=0;i<vm_mngr->memory_w.num; i++) {
		if (vm_mngr->exception_flags & EXCEPT_CODE_AUTOMOD)
			break;
		if (vm_mngr->memory_w.array[i].stop <= vm_mngr->code_bloc_pool_ad_min ||
		    vm_mngr->memory_w.array[i].start >=vm_mngr->code_bloc_pool_ad_max)
			continue;

		LIST_FOREACH(cbp, &vm_mngr->code_bloc_pool, next){
			if ((cbp->ad_start < vm_mngr->memory_w.array[i].stop) &&
			    (vm_mngr->memory_w.array[i].start < cbp->ad_stop)){
#ifdef DEBUG_MIASM_AUTOMOD_CODE
				fprintf(stderr, "**********************************\n");
				fprintf(stderr, "self modifying code %"PRIX64" %"PRIX64"\n",
					vm_mngr->memory_w.array[i].start,
					vm_mngr->memory_w.array[i].stop);
				fprintf(stderr, "**********************************\n");
#endif
				vm_mngr->exception_flags |= EXCEPT_CODE_AUTOMOD;
				break;
			}
		}
	}
}


void check_memory_breakpoint(vm_mngr_t* vm_mngr)
{
	int i;
	struct memory_breakpoint_info * memory_bp;

	/* Check memory breakpoints */
	LIST_FOREACH(memory_bp, &vm_mngr->memory_breakpoint_pool, next) {
		if (vm_mngr->exception_flags & EXCEPT_BREAKPOINT_INTERN)
			break;
		if (memory_bp->access & BREAKPOINT_READ) {
			for (i=0;i<vm_mngr->memory_r.num; i++) {
				if ((memory_bp->ad < vm_mngr->memory_r.array[i].stop) &&
				    (vm_mngr->memory_r.array[i].start < memory_bp->ad + memory_bp->size)) {
					vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_INTERN;
					break;
				}
			}
		}
		if (memory_bp->access & BREAKPOINT_WRITE) {
			for (i=0;i<vm_mngr->memory_w.num; i++) {
				if ((memory_bp->ad < vm_mngr->memory_w.array[i].stop) &&
				    (vm_mngr->memory_w.array[i].start < memory_bp->ad + memory_bp->size)) {
					vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_INTERN;
					break;
				}
			}
		}
	}
}


PyObject* get_memory_pylist(vm_mngr_t* vm_mngr, struct memory_access_list* memory_list)
{
	int i;
	PyObject *pylist;
	PyObject *range;
	pylist = PyList_New(memory_list->num);
	for (i=0;i<memory_list->num;i++) {
		range = PyTuple_New(2);
		PyTuple_SetItem(range, 0, PyLong_FromUnsignedLongLong((uint64_t)memory_list->array[i].start));
		PyTuple_SetItem(range, 1, PyLong_FromUnsignedLongLong((uint64_t)memory_list->array[i].stop));
		PyList_SetItem(pylist, i, range);
	}
	return pylist;

}

PyObject* get_memory_read(vm_mngr_t* vm_mngr)
{
	return get_memory_pylist(vm_mngr, &vm_mngr->memory_r);
}

PyObject* get_memory_write(vm_mngr_t* vm_mngr)
{
	return get_memory_pylist(vm_mngr, &vm_mngr->memory_w);
}

void vm_MEM_WRITE_08(vm_mngr_t* vm_mngr, uint64_t addr, unsigned char src)
{
	add_mem_write(vm_mngr, addr, 1);
	memory_page_write(vm_mngr, 8, addr, src);
}

void vm_MEM_WRITE_16(vm_mngr_t* vm_mngr, uint64_t addr, unsigned short src)
{
	add_mem_write(vm_mngr, addr, 2);
	memory_page_write(vm_mngr, 16, addr, src);
}
void vm_MEM_WRITE_32(vm_mngr_t* vm_mngr, uint64_t addr, unsigned int src)
{
	add_mem_write(vm_mngr, addr, 4);
	memory_page_write(vm_mngr, 32, addr, src);
}
void vm_MEM_WRITE_64(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t src)
{
	add_mem_write(vm_mngr, addr, 8);
	memory_page_write(vm_mngr, 64, addr, src);
}

unsigned char vm_MEM_LOOKUP_08(vm_mngr_t* vm_mngr, uint64_t addr)
{
	unsigned char ret;
	add_mem_read(vm_mngr, addr, 1);
	ret = memory_page_read(vm_mngr, 8, addr);
	return ret;
}
unsigned short vm_MEM_LOOKUP_16(vm_mngr_t* vm_mngr, uint64_t addr)
{
	unsigned short ret;
	add_mem_read(vm_mngr, addr, 2);
	ret = memory_page_read(vm_mngr, 16, addr);
	return ret;
}
unsigned int vm_MEM_LOOKUP_32(vm_mngr_t* vm_mngr, uint64_t addr)
{
	unsigned int ret;
	add_mem_read(vm_mngr, addr, 4);
	ret = memory_page_read(vm_mngr, 32, addr);
	return ret;
}
uint64_t vm_MEM_LOOKUP_64(vm_mngr_t* vm_mngr, uint64_t addr)
{
	uint64_t ret;
	add_mem_read(vm_mngr, addr, 8);
	ret = memory_page_read(vm_mngr, 64, addr);
	return ret;
}


int vm_read_mem(vm_mngr_t* vm_mngr, uint64_t addr, char** buffer_ptr, uint64_t size)
{
       char* buffer;
       uint64_t len;
       struct memory_page_node * mpn;

       buffer = malloc(size);
       *buffer_ptr = buffer;
       if (!buffer){
	      fprintf(stderr, "Error: cannot alloc read\n");
	      exit(-1);
       }

       /* read is multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 1);
	      if (!mpn){
		      free(*buffer_ptr);
		      PyErr_SetString(PyExc_RuntimeError, "Error: cannot find address");
		      return -1;
	      }

	      len = MIN(size, mpn->size - (addr - mpn->ad));
	      memcpy(buffer, (char*)(mpn->ad_hp + (addr - mpn->ad)), len);
	      buffer += len;
	      addr += len;
	      size -= len;
       }

       return 0;
}

int vm_write_mem(vm_mngr_t* vm_mngr, uint64_t addr, char *buffer, uint64_t size)
{
       uint64_t len;
       struct memory_page_node * mpn;

       /* write is multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 1);
	      if (!mpn){
		      PyErr_SetString(PyExc_RuntimeError, "Error: cannot find address");
		      return -1;
	      }

	      len = MIN(size, mpn->size - (addr - mpn->ad));
	      memcpy(mpn->ad_hp + (addr-mpn->ad), buffer, len);
	      buffer += len;
	      addr += len;
	      size -= len;
       }

       return 0;
}



int is_mapped(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size)
{
       uint64_t len;
       struct memory_page_node * mpn;

       /* test multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 0);
	      if (!mpn)
		      return 0;

	      len = MIN(size, mpn->size - (addr - mpn->ad));
	      addr += len;
	      size -= len;
       }

       return 1;
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

uint64_t shift_right_logic(uint64_t size,
			   uint64_t a, uint64_t b)
{
    uint64_t u32_a;
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
		    fprintf(stderr, "inv size in shift %"PRIx64"\n", size);
		    exit(0);
    }
}

uint64_t shift_left_logic(uint64_t size, uint64_t a, uint64_t b)
{
    switch(size){
	    case 8:
		    return (a<<b)&0xff;
	    case 16:
		    return (a<<b)&0xffff;
	    case 32:
		    return (a<<b)&0xffffffff;
	    case 64:
		    return (a<<b)&0xffffffffffffffff;
	    default:
		    fprintf(stderr, "inv size in shift %"PRIx64"\n", size);
		    exit(0);
    }
}

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
	res = (int64_t)a*(int64_t)b;
	return res>>32ULL;
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

uint64_t rot_left(uint64_t size, uint64_t a, uint64_t b)
{
    uint64_t tmp;

    b = b&0x3F;
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
	    case 64:
		    tmp = (a << b) | ((a&0xFFFFFFFFFFFFFFFF) >> (size-b));
		    return tmp&0xFFFFFFFFFFFFFFFF;
	    default:
		    fprintf(stderr, "inv size in rotleft %"PRIX64"\n", size);
		    exit(0);
    }
}

uint64_t rot_right(uint64_t size, uint64_t a, uint64_t b)
{
    uint64_t tmp;

    b = b&0x3F;
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
	    case 64:
		    tmp = ((a&0xFFFFFFFFFFFFFFFF) >> b) | (a << (size-b));
		    return tmp&0xFFFFFFFFFFFFFFFF;
	    default:
		    fprintf(stderr, "inv size in rotright %"PRIX64"\n", size);
		    exit(0);
    }
}


unsigned int rcl_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
    uint64_t tmp;
    uint64_t tmp_count;
    uint64_t tmp_cf;

    tmp = a;
    // TODO 64bit mode
    tmp_count = (b & 0x1f) % (size + 1);
    while (tmp_count != 0) {
	    tmp_cf = (tmp >> (size - 1)) & 1;
	    tmp = (tmp << 1) + cf;
	    cf = tmp_cf;
	    tmp_count -= 1;
    }
    return tmp;
}

unsigned int rcr_rez_op(unsigned int size, unsigned int a, unsigned int b, unsigned int cf)
{
    uint64_t tmp;
    uint64_t tmp_count;
    uint64_t tmp_cf;

    tmp = a;
    // TODO 64bit mode
    tmp_count = (b & 0x1f) % (size + 1);
    while (tmp_count != 0) {
	    tmp_cf = tmp & 1;
	    tmp = (tmp >> 1) + (cf << (size - 1));
	    cf = tmp_cf;
	    tmp_count -= 1;
    }
    return tmp;
}

unsigned int x86_bsr(unsigned int size, uint64_t src)
{
	int i;

	for (i=size-1; i>=0; i--){
		if (src & (1<<i))
			return i;
	}
	fprintf(stderr, "sanity check error bsr\n");
	exit(0);
}

unsigned int x86_bsf(unsigned int size, uint64_t src)
{
	int i;

	for (i=0; i<size; i++){
		if (src & (1<<i))
			return i;
	}
	fprintf(stderr, "sanity check error bsf\n");
	exit(0);
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

//#define DEBUG_MIASM_DOUBLE

void dump_float(void)
{
	/*
	printf("%e\n", vmmngr.float_st0);
	printf("%e\n", vmmngr.float_st1);
	printf("%e\n", vmmngr.float_st2);
	printf("%e\n", vmmngr.float_st3);
	printf("%e\n", vmmngr.float_st4);
	printf("%e\n", vmmngr.float_st5);
	printf("%e\n", vmmngr.float_st6);
	printf("%e\n", vmmngr.float_st7);
	*/
}

double mem_32_to_double(unsigned int m)
{
	float f;
	double d;

	f = *((float*)&m);
	d = f;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%d float %e\n", m, d);
#endif
	return d;
}


double mem_64_to_double(uint64_t m)
{
	double d;
	d = *((double*)&m);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%"PRId64" double %e\n", m, d);
#endif
	return d;
}

double int_16_to_double(unsigned int m)
{
	double d;

	d = (double)(m&0xffff);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%d double %e\n", m, d);
#endif
	return d;
}

double int_32_to_double(unsigned int m)
{
	double d;

	d = (double)m;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%d double %e\n", m, d);
#endif
	return d;
}

double int_64_to_double(uint64_t m)
{
	double d;

	d = (double)m;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%"PRId64" double %e\n", m, d);
#endif
	return d;
}

int16_t double_to_int_16(double d)
{
	int16_t i;

	i = (int16_t)d;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e int %d\n", d, i);
#endif
	return i;
}

int32_t double_to_int_32(double d)
{
	int32_t i;

	i = (int32_t)d;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e int %d\n", d, i);
#endif
	return i;
}

int64_t double_to_int_64(double d)
{
	int64_t i;

	i = (int64_t)d;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e int %"PRId64"\n", d, i);
#endif
	return i;
}


double fadd(double a, double b)
{
	double c;
	c = a + b;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e + %e -> %e\n", a, b, c);
#endif
	return c;
}

double fsub(double a, double b)
{
	double c;
	c = a - b;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e - %e -> %e\n", a, b, c);
#endif
	return c;
}

double fmul(double a, double b)
{
	double c;
	c = a * b;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e * %e -> %e\n", a, b, c);
#endif
	return c;
}

double fdiv(double a, double b)
{
	double c;
	c = a / b;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e / %e -> %e\n", a, b, c);
#endif
	return c;
}

double ftan(double a)
{
	double b;
	b = tan(a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e tan %e\n", a, b);
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
	dump_float();
	printf("%e double %e\n", a, c);
#endif
	return c;
}

double fsin(double a)
{
	double b;
	b = sin(a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e sin %e\n", a, b);
#endif
	return b;
}

double fcos(double a)
{
	double b;
	b = cos(a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e cos %e\n", a, b);
#endif
	return b;
}


double fscale(double a, double b)
{
	double c;
	c = a * exp2(trunc(b));
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e *exp2 %e -> %e\n", a, b, c);
#endif
	return c;
}

double f2xm1(double a)
{
	double b;
	b = exp2(a)-1;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e exp2 -1 %e\n", a, b);
#endif
	return b;
}

double fsqrt(double a)
{
	double b;
	b = sqrt(a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e sqrt %e\n", a, b);
#endif
	return b;
}

double fabs(double a)
{
	double b;
	b = abs(a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e abs %e\n", a, b);
#endif
	return b;
}

double fprem(double a, double b)
{
	double c;
	c = fmod(a, b);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e %% %e -> %e\n", a, b, c);
#endif
	return c;
}

unsigned int fprem_lsb(double a, double b)
{
	// Inspired from qemu/fpu_helper.c
	double c;
	signed long long int q;
	c = a / b; /* ST0 / ST1 */
	/* round dblq towards zero */
	c = (c < 0.0) ? ceil(c) : floor(c);

	/* convert dblq to q by truncating towards zero */
	if (c < 0.0) {
	    q = (signed long long int)(-c);
	} else {
	    q = (signed long long int)c;
	}
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e %% %e -> %d %d %d\n", a, b, q & 0x4,
	       q & 0x2, q & 0x1);
#endif
	return q;
}

double fchs(double a)
{
	double b;
	b = -a;
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf(" - %e -> %e\n", a, b);
#endif
	return b;
}

double fyl2x(double a, double b)
{
	double c;
	c = b * (log(a) / log(2));
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%e * log(%e) -> %e\n", b, a, c);
#endif
	return c;
}

double fpatan(double a, double b)
{
	double c;
	c = atan2(b, a);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("arctan(%e / %e) -> %e\n", b, a, c);
#endif
	return c;
}

unsigned int fcom_c0(double a, double b)
{
	if (isnan(a) || isnan(b))
		return 1;
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
	if (isnan(a) || isnan(b))
		return 1;
	return 0;
}
unsigned int fcom_c3(double a, double b)
{
	if (isnan(a) || isnan(b))
		return 1;
	if (a==b)
		return 1;
	return 0;
}

unsigned int fxam_c0(double a)
{
	switch(fpclassify(a)) {
		case FP_NAN:
			return 1;
		case FP_NORMAL:
			return 0;
		case FP_INFINITE:
			return 1;
		case FP_ZERO:
			return 0;
		case FP_SUBNORMAL:
			return 0;
		default:
			// ClassEmpty
			// ClassUnsupported
			return 0;
	}
}

unsigned int fxam_c1(double a)
{
	if ((a < 0) || isnan(a))
		return 1;
	return 0;
}

unsigned int fxam_c2(double a)
{
	switch(fpclassify(a)) {
		case FP_NAN:
			return 0;
		case FP_NORMAL:
			return 1;
		case FP_INFINITE:
			return 1;
		case FP_ZERO:
			return 0;
		case FP_SUBNORMAL:
			return 1;
		default:
			// ClassEmpty
			// ClassUnsupported
			return 0;
	}
}

unsigned int fxam_c3(double a)
{
	switch(fpclassify(a)) {
		case FP_NAN:
			return 0;
		case FP_NORMAL:
			return 0;
		case FP_INFINITE:
			return 0;
		case FP_ZERO:
			return 1;
		case FP_SUBNORMAL:
			return 1;
		default:
			// ClassEmpty
			// ClassUnsupported
			return 0;
	}
}

unsigned int double_to_mem_32(double d)
{
	unsigned int m;
	float f;
	f = d;
	m = *((unsigned int*)&f);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%d %e\n", m, d);
#endif
	return m;
}

uint64_t double_to_mem_64(double d)
{
	uint64_t m;
	m = *((uint64_t*)&d);
#ifdef DEBUG_MIASM_DOUBLE
	dump_float();
	printf("%"PRId64" %e\n", m, d);
#endif
	return m;
}

struct memory_page_node * create_memory_page_node(uint64_t ad, unsigned int size, unsigned int access, char* name)
{
	struct memory_page_node * mpn;
	void* ad_hp;

	mpn = malloc(sizeof(*mpn));
	if (!mpn){
		fprintf(stderr, "Error: cannot alloc mpn\n");
		return NULL;
	}
	ad_hp = malloc(size);
	if (!ad_hp){
		free(mpn);
		fprintf(stderr, "Error: cannot alloc %d\n", size);
		return NULL;
	}
	mpn->name = malloc(strlen(name) + 1);
	if (!mpn->name){
		free(mpn);
		free(ad_hp);
		fprintf(stderr, "Error: cannot alloc\n");
		return NULL;
	}

	mpn->ad = ad;
	mpn->size = size;
	mpn->access = access;
	mpn->ad_hp = ad_hp;
	strcpy(mpn->name, name);

	return mpn;
}


struct code_bloc_node * create_code_bloc_node(uint64_t ad_start, uint64_t ad_stop)
{
	struct code_bloc_node * cbp;

	cbp = malloc(sizeof(*cbp));
	if (!cbp){
		fprintf(stderr, "Error: cannot alloc cbp\n");
		exit(-1);
	}

	cbp->ad_start = ad_start;
	cbp->ad_stop = ad_stop;

	return cbp;
}


void add_code_bloc(vm_mngr_t* vm_mngr, struct code_bloc_node* cbp)
{
	LIST_INSERT_HEAD(&vm_mngr->code_bloc_pool, cbp, next);
	if (vm_mngr->code_bloc_pool_ad_min> cbp->ad_start)
		vm_mngr->code_bloc_pool_ad_min = cbp->ad_start;
	if (vm_mngr->code_bloc_pool_ad_max< cbp->ad_stop)
		vm_mngr->code_bloc_pool_ad_max = cbp->ad_stop;
}

void dump_code_bloc_pool(vm_mngr_t* vm_mngr)
{
	struct code_bloc_node * cbp;

	LIST_FOREACH(cbp, &vm_mngr->code_bloc_pool, next){
		printf("ad start %"PRIX64" ad_stop %"PRIX64"\n",
		       cbp->ad_start,
		       cbp->ad_stop);
	}
}


void init_memory_page_pool(vm_mngr_t* vm_mngr)
{

	vm_mngr->memory_pages_number = 0;
	vm_mngr->memory_pages_array = NULL;
}

void init_code_bloc_pool(vm_mngr_t* vm_mngr)
{
	LIST_INIT(&vm_mngr->code_bloc_pool);
	vm_mngr->code_bloc_pool_ad_min = 0xffffffffffffffffULL;
	vm_mngr->code_bloc_pool_ad_max = 0;

	memory_access_list_init(&(vm_mngr->memory_r));
	memory_access_list_init(&(vm_mngr->memory_w));


}

void init_memory_breakpoint(vm_mngr_t* vm_mngr)
{
	LIST_INIT(&vm_mngr->memory_breakpoint_pool);
}


void reset_memory_page_pool(vm_mngr_t* vm_mngr)
{
	struct memory_page_node * mpn;
	int i;
	for (i=0;i<vm_mngr->memory_pages_number; i++) {
		mpn = &vm_mngr->memory_pages_array[i];
		free(mpn->ad_hp);
		free(mpn->name);
	}
	free(vm_mngr->memory_pages_array);
	vm_mngr->memory_pages_array = NULL;
	vm_mngr->memory_pages_number = 0;
}


void reset_code_bloc_pool(vm_mngr_t* vm_mngr)
{
	struct code_bloc_node * cbp;


	while (!LIST_EMPTY(&vm_mngr->code_bloc_pool)) {
		cbp = LIST_FIRST(&vm_mngr->code_bloc_pool);
		LIST_REMOVE(cbp, next);
		free(cbp);
	}
	vm_mngr->code_bloc_pool_ad_min = 0xffffffffffffffffULL;
	vm_mngr->code_bloc_pool_ad_max = 0;
}

void reset_memory_access(vm_mngr_t* vm_mngr)
{
	memory_access_list_reset(&(vm_mngr->memory_r));
	memory_access_list_reset(&(vm_mngr->memory_w));
}

void reset_memory_breakpoint(vm_mngr_t* vm_mngr)
{
	struct memory_breakpoint_info * mpn;

	while (!LIST_EMPTY(&vm_mngr->memory_breakpoint_pool)) {
		mpn = LIST_FIRST(&vm_mngr->memory_breakpoint_pool);
		LIST_REMOVE(mpn, next);
		free(mpn);
	}

}



/* We don't use dichotomy here for the insertion */
int is_mpn_in_tab(vm_mngr_t* vm_mngr, struct memory_page_node* mpn_a)
{
	struct memory_page_node * mpn;
	int i;

	for (i=0;i<vm_mngr->memory_pages_number; i++) {
		mpn = &vm_mngr->memory_pages_array[i];
		if (mpn->ad >= mpn_a->ad + mpn_a->size)
			continue;
		if (mpn->ad + mpn->size  <= mpn_a->ad)
			continue;
		fprintf(stderr,
			"Error: attempt to add page (0x%"PRIX64" 0x%"PRIX64") "
			"overlapping page (0x%"PRIX64" 0x%"PRIX64")\n",
			mpn_a->ad, mpn_a->ad + mpn_a->size,
			mpn->ad, mpn->ad + mpn->size);

		return 1;
	}

	return 0;
}


/* We don't use dichotomy here for the insertion */
void add_memory_page(vm_mngr_t* vm_mngr, struct memory_page_node* mpn_a)
{
	struct memory_page_node * mpn;
	int i;

	for (i=0; i < vm_mngr->memory_pages_number; i++) {
		mpn = &vm_mngr->memory_pages_array[i];
		if (mpn->ad < mpn_a->ad)
			continue;
		break;
	}
	vm_mngr->memory_pages_array = realloc(vm_mngr->memory_pages_array,
					      sizeof(struct memory_page_node) *
					      (vm_mngr->memory_pages_number+1));

	memmove(&vm_mngr->memory_pages_array[i+1],
		&vm_mngr->memory_pages_array[i],
		sizeof(struct memory_page_node) * (vm_mngr->memory_pages_number - i)
		);

	vm_mngr->memory_pages_array[i] = *mpn_a;
	vm_mngr->memory_pages_number ++;

}

/* Return a char* representing the repr of vm_mngr_t object */
char* dump(vm_mngr_t* vm_mngr)
{
	char buf[0x100];
	int length;
	char *buf_final;
	int i;
	char buf_addr[0x20];
	char buf_size[0x20];
	struct memory_page_node * mpn;
	/*             0x1234567812345678 0x1234567812345678        */
	char* intro = "Addr               Size               Access Comment\n";
	int total_len = strlen(intro) + 1;

	buf_final = malloc(total_len);
	if (buf_final == NULL) {
		fprintf(stderr, "Error: cannot alloc\n");
		exit(0);
	}
	strcpy(buf_final, intro);
	for (i=0; i< vm_mngr->memory_pages_number; i++) {
		mpn = &vm_mngr->memory_pages_array[i];
		snprintf(buf_addr, sizeof(buf_addr),
			 "0x%"PRIX64, (uint64_t)mpn->ad);
		snprintf(buf_size, sizeof(buf_size),
			 "0x%"PRIX64, (uint64_t)mpn->size);

		length = snprintf(buf, sizeof(buf) - 1,
				  "%-18s %-18s %c%c%c    %s",
				  buf_addr,
				  buf_size,
				  mpn->access & PAGE_READ? 'R':'_',
				  mpn->access & PAGE_WRITE? 'W':'_',
				  mpn->access & PAGE_EXEC? 'X':'_',
				  mpn->name
				  );
		strcat(buf, "\n");
		total_len += length + 1 + 1;
		buf_final = realloc(buf_final, total_len);
		if (buf_final == NULL) {
			fprintf(stderr, "Error: cannot alloc\n");
			exit(0);
		}
		strcat(buf_final, buf);
	}

	return buf_final;
}

void dump_memory_breakpoint_pool(vm_mngr_t* vm_mngr)
{
	struct memory_breakpoint_info * mpn;

	LIST_FOREACH(mpn, &vm_mngr->memory_breakpoint_pool, next){
		printf("ad %"PRIX64" size %"PRIX64" access %"PRIX64"\n",
		       mpn->ad,
		       mpn->size,
		       mpn->access
		       );
	}
}


void add_memory_breakpoint(vm_mngr_t* vm_mngr, uint64_t ad, uint64_t size, unsigned int access)
{
	struct memory_breakpoint_info * mpn_a;
	mpn_a = malloc(sizeof(*mpn_a));
	if (!mpn_a) {
		fprintf(stderr, "Error: cannot alloc\n");
		exit(0);
	}
	mpn_a->ad = ad;
	mpn_a->size = size;
	mpn_a->access = access;

	LIST_INSERT_HEAD(&vm_mngr->memory_breakpoint_pool, mpn_a, next);

}

void remove_memory_breakpoint(vm_mngr_t* vm_mngr, uint64_t ad, unsigned int access)
{
	struct memory_breakpoint_info * mpn;

	LIST_FOREACH(mpn, &vm_mngr->memory_breakpoint_pool, next){
		if (mpn->ad == ad && mpn->access == access)
			LIST_REMOVE(mpn, next);
	}

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


// Return vm_mngr's exception flag value
uint64_t get_exception_flag(vm_mngr_t* vm_mngr)
{
	return vm_mngr->exception_flags;
}


