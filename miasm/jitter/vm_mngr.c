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
#include "vm_mngr.h"

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "queue.h"



/****************memory manager**************/




#define MIN(a,b)  (((a)<(b))?(a):(b))
#define MAX(a,b)  (((a)>(b))?(a):(b))

// #define DEBUG_MIASM_AUTOMOD_CODE
#define MEMORY_ACCESS_LIST_INITIAL_COUNT 100

/*
  To avoid alloc/free for each instruction access, the buffer is allocated here,
  and is increased depending of program needs.
 */
void memory_access_list_init(struct memory_access_list * access)
{
	access->array = malloc(MEMORY_ACCESS_LIST_INITIAL_COUNT * sizeof(struct memory_access));
	if (access->array == NULL) {
		fprintf(stderr, "cannot realloc struct memory_access access->array\n");
		exit(EXIT_FAILURE);
	}
	access->allocated = MEMORY_ACCESS_LIST_INITIAL_COUNT;
	access->num = 0;
}

void memory_access_list_reset(struct memory_access_list * access)
{
	access->num = 0;
}

void memory_access_list_add(struct memory_access_list * access, uint64_t start, uint64_t stop)
{
	if (access->num >= access->allocated) {
		if (access->allocated == 0)
			access->allocated = 1;
		else {
			if (access->allocated >= SIZE_MAX / 2) {
				fprintf(stderr, "Cannot alloc more pages\n");
				exit(EXIT_FAILURE);
			}
			access->allocated *= 2;
		}
		access->array = realloc(access->array, access->allocated * sizeof(struct memory_access));
		if (access->array == NULL) {
			fprintf(stderr, "cannot realloc struct memory_access access->array\n");
			exit(EXIT_FAILURE);
		}
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

int midpoint(int imin, int imax)
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
			vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_MEMORY;
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
			ret = set_endian16(vm_mngr, (uint16_t)ret);
			break;
		case 32:
			ret = *((unsigned int*)addr)&0xFFFFFFFF;
			ret = set_endian32(vm_mngr, (uint32_t)ret);
			break;
		case 64:
			ret = *((uint64_t*)addr)&0xFFFFFFFFFFFFFFFFULL;
			ret = set_endian64(vm_mngr, ret);
			break;
		default:
			fprintf(stderr, "Bad memory access size %d\n", my_size);
			exit(EXIT_FAILURE);
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
			break;
		case 16:
			ret = set_endian16(vm_mngr, (uint16_t)ret);
			break;
		case 32:
			ret = set_endian32(vm_mngr, (uint32_t)ret);
			break;
		case 64:
			ret = set_endian64(vm_mngr, ret);
			break;
		default:
			fprintf(stderr, "Bad memory access size %d\n", my_size);
			exit(EXIT_FAILURE);
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
			vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_MEMORY;
	}

	addr = &((unsigned char*)mpn->ad_hp)[ad - mpn->ad];

	/* write fits in a page */
	if (ad - mpn->ad + my_size/8 <= mpn->size){
		switch(my_size){
		case 8:
			*((unsigned char*)addr) = src&0xFF;
			break;
		case 16:
			src = set_endian16(vm_mngr, (uint16_t)src);
			*((unsigned short*)addr) = src&0xFFFF;
			break;
		case 32:
			src = set_endian32(vm_mngr, (uint32_t)src);
			*((unsigned int*)addr) = src&0xFFFFFFFF;
			break;
		case 64:
			src = set_endian64(vm_mngr, src);
			*((uint64_t*)addr) = src&0xFFFFFFFFFFFFFFFFULL;
			break;
		default:
			fprintf(stderr, "Bad memory access size %d\n", my_size);
			exit(EXIT_FAILURE);
			break;
		}
	}
	/* write is multiple page wide */
	else{
		switch(my_size){

		case 8:
			break;
		case 16:
			src = set_endian16(vm_mngr, (uint16_t)src);
			break;
		case 32:
			src = set_endian32(vm_mngr, (uint32_t)src);
			break;
		case 64:
			src = set_endian64(vm_mngr, src);
			break;
		default:
			fprintf(stderr, "Bad memory access size %d\n", my_size);
			exit(EXIT_FAILURE);
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
	size_t i;
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
	size_t i;
	struct memory_breakpoint_info * memory_bp;

	/* Check memory breakpoints */
	LIST_FOREACH(memory_bp, &vm_mngr->memory_breakpoint_pool, next) {
		if (vm_mngr->exception_flags & EXCEPT_BREAKPOINT_MEMORY)
			break;
		if (memory_bp->access & BREAKPOINT_READ) {
			for (i=0;i<vm_mngr->memory_r.num; i++) {
				if ((memory_bp->ad < vm_mngr->memory_r.array[i].stop) &&
				    (vm_mngr->memory_r.array[i].start < memory_bp->ad + memory_bp->size)) {
					vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_MEMORY;
					break;
				}
			}
		}
		if (memory_bp->access & BREAKPOINT_WRITE) {
			for (i=0;i<vm_mngr->memory_w.num; i++) {
				if ((memory_bp->ad < vm_mngr->memory_w.array[i].stop) &&
				    (vm_mngr->memory_w.array[i].start < memory_bp->ad + memory_bp->size)) {
					vm_mngr->exception_flags |= EXCEPT_BREAKPOINT_MEMORY;
					break;
				}
			}
		}
	}
}


PyObject* get_memory_pylist(vm_mngr_t* vm_mngr, struct memory_access_list* memory_list)
{
	size_t i;
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
	ret = (unsigned char)memory_page_read(vm_mngr, 8, addr);
	return ret;
}
unsigned short vm_MEM_LOOKUP_16(vm_mngr_t* vm_mngr, uint64_t addr)
{
	unsigned short ret;
	add_mem_read(vm_mngr, addr, 2);
	ret = (unsigned short)memory_page_read(vm_mngr, 16, addr);
	return ret;
}
unsigned int vm_MEM_LOOKUP_32(vm_mngr_t* vm_mngr, uint64_t addr)
{
	unsigned int ret;
	add_mem_read(vm_mngr, addr, 4);
	ret = (unsigned int)memory_page_read(vm_mngr, 32, addr);
	return ret;
}
uint64_t vm_MEM_LOOKUP_64(vm_mngr_t* vm_mngr, uint64_t addr)
{
	uint64_t ret;
	add_mem_read(vm_mngr, addr, 8);
	ret = memory_page_read(vm_mngr, 64, addr);
	return ret;
}


int vm_read_mem(vm_mngr_t* vm_mngr, uint64_t addr, char** buffer_ptr, size_t size)
{
       char* buffer;
       size_t len;
       uint64_t addr_diff;
       size_t addr_diff_st;
       struct memory_page_node * mpn;

       buffer = malloc(size);
       *buffer_ptr = buffer;
       if (!buffer){
	      fprintf(stderr, "Error: cannot alloc read\n");
	      exit(EXIT_FAILURE);
       }

       /* read is multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 1);
	      if (!mpn){
		      free(*buffer_ptr);
		      PyErr_SetString(PyExc_RuntimeError, "Error: cannot find address");
		      return -1;
	      }

	      addr_diff = addr - mpn->ad;
	      if (addr_diff > SIZE_MAX) {
		      fprintf(stderr, "Size too big\n");
		      exit(EXIT_FAILURE);
	      }
	      addr_diff_st = (size_t) addr_diff;
	      len = MIN(size, mpn->size - addr_diff_st);
	      memcpy(buffer, (char*)mpn->ad_hp + (addr_diff_st), len);
	      buffer += len;
	      addr += len;
	      size -= len;
       }

       return 0;
}


/*
   Try to read @size bytes from vm mmemory
   Return the number of bytes consecutively read
*/
uint64_t vm_read_mem_ret_buf(vm_mngr_t* vm_mngr, uint64_t addr, size_t size, char *buffer)
{
	size_t len;
	uint64_t addr_diff;
	uint64_t size_out;
	size_t addr_diff_st;

	struct memory_page_node * mpn;

	size_out = 0;
	/* read is multiple page wide */
	while (size){
		mpn = get_memory_page_from_address(vm_mngr, addr, 0);
		if (!mpn){
			return size_out;
		}

		addr_diff = addr - mpn->ad;
		if (addr_diff > SIZE_MAX) {
			fprintf(stderr, "Size too big\n");
			exit(EXIT_FAILURE);
		}
		addr_diff_st = (size_t) addr_diff;
		len = MIN(size, mpn->size - addr_diff_st);
		memcpy(buffer, (char*)mpn->ad_hp + (addr_diff_st), len);
		buffer += len;
		size_out += len;
		addr += len;
		size -= len;
	}

	return size_out;
}


int vm_write_mem(vm_mngr_t* vm_mngr, uint64_t addr, char *buffer, size_t size)
{
       size_t len;
       uint64_t addr_diff;
       size_t addr_diff_st;
       struct memory_page_node * mpn;

       if (size > SIZE_MAX) {
	       fprintf(stderr, "Write size wider than supported system\n");
	       exit(EXIT_FAILURE);
       }

       /* write is multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 1);
	      if (!mpn){
		      PyErr_SetString(PyExc_RuntimeError, "Error: cannot find address");
		      return -1;
	      }

	      addr_diff = addr - mpn->ad;
	      if (addr_diff > SIZE_MAX) {
		      fprintf(stderr, "Size too big\n");
		      exit(EXIT_FAILURE);
	      }
	      addr_diff_st = (size_t) addr_diff;
	      len = MIN(size, mpn->size - addr_diff_st);
	      memcpy((char*)mpn->ad_hp + addr_diff_st, buffer, len);
	      buffer += len;
	      addr += len;
	      size -= len;
       }

       return 0;
}



int is_mapped(vm_mngr_t* vm_mngr, uint64_t addr, size_t size)
{
       size_t len;
       uint64_t addr_diff;
       size_t addr_diff_st;
       struct memory_page_node * mpn;

       if (size > SIZE_MAX) {
	       fprintf(stderr, "Test size wider than supported system\n");
	       exit(EXIT_FAILURE);
       }

       /* test multiple page wide */
       while (size){
	      mpn = get_memory_page_from_address(vm_mngr, addr, 0);
	      if (!mpn)
		      return 0;

	      addr_diff = addr - mpn->ad;
	      if (addr_diff > SIZE_MAX) {
		      fprintf(stderr, "Size too big\n");
		      exit(EXIT_FAILURE);
	      }
	      addr_diff_st = (size_t) addr_diff;
	      len = MIN(size, mpn->size - addr_diff_st);
	      addr += len;
	      size -= len;
       }

       return 1;
}

struct memory_page_node * create_memory_page_node(uint64_t ad, size_t size, unsigned int access, const char *name)
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
		fprintf(stderr, "Error: cannot alloc %zu\n", size);
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
		exit(EXIT_FAILURE);
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
	if (vm_mngr->memory_pages_array == NULL) {
		fprintf(stderr, "cannot realloc struct memory_page_node vm_mngr->memory_pages_array\n");
		exit(EXIT_FAILURE);
	}


	memmove(&vm_mngr->memory_pages_array[i+1],
		&vm_mngr->memory_pages_array[i],
		sizeof(struct memory_page_node) * (vm_mngr->memory_pages_number - i)
		);

	vm_mngr->memory_pages_array[i] = *mpn_a;
	vm_mngr->memory_pages_number ++;
}

void remove_memory_page(vm_mngr_t* vm_mngr, uint64_t ad)
{
  struct memory_page_node * mpn;
  int i;

  i = find_page_node(vm_mngr->memory_pages_array,
		     ad,
		     0,
		     vm_mngr->memory_pages_number - 1);
  if (i < 0) {
    return;
  }

  mpn = &vm_mngr->memory_pages_array[i];
  free(mpn->name);
  free(mpn->ad_hp);
  memmove(&vm_mngr->memory_pages_array[i],
  	      &vm_mngr->memory_pages_array[i+1],
  	      sizeof(struct memory_page_node) * (vm_mngr->memory_pages_number - i - 1)
  	      );
  vm_mngr->memory_pages_number --;
  vm_mngr->memory_pages_array = realloc(vm_mngr->memory_pages_array,
					sizeof(struct memory_page_node) *
					(vm_mngr->memory_pages_number));
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
	size_t total_len = strlen(intro) + 1;

	buf_final = malloc(total_len);
	if (buf_final == NULL) {
		fprintf(stderr, "Error: cannot alloc char* buf_final\n");
		exit(EXIT_FAILURE);
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
			fprintf(stderr, "cannot realloc char* buf_final\n");
			exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
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
  unsigned int i, j, last;
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
_MIASM_EXPORT uint64_t get_exception_flag(vm_mngr_t* vm_mngr)
{
	return vm_mngr->exception_flags;
}
