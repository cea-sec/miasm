#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../jitter/queue.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"

#include "taint_analysis.h"


/* Taint setters/getters */
/* Colors */
struct taint_colors_t*
taint_init_colors(uint64_t nb_colors, uint64_t nb_registers)
{
	// NOTE: use unsigned pour nb_colors et nb_regs
	struct taint_colors_t* taint_colors;

	taint_colors = malloc(sizeof(*taint_colors));
	if (taint_colors == NULL)
	{
		fprintf(stderr, "cannot alloc taint_colors\n");
		exit(EXIT_FAILURE);
	}

	taint_colors->colors = malloc(nb_colors*sizeof(*taint_colors->colors));
	if (taint_colors->colors == NULL)
	{
		fprintf(stderr, "cannot alloc taint_colors->colors\n");
		exit(EXIT_FAILURE);
	}

	taint_colors->nb_colors = nb_colors;
	taint_colors->nb_registers = nb_registers;

	int i;
	struct taint_color_t *taint_analysis;
	for (i = 0 ; i < nb_colors ; i++)
	{
		taint_colors->colors[i] = taint_init_color(nb_registers);
	}

	return taint_colors;
}

struct taint_color_t
taint_init_color(uint64_t nb_registers)
{
	struct taint_color_t taint_analysis;

	/* Init registers */
	taint_analysis.registers
		= calloc((nb_registers/NB_BITS_IN_UINT32_T+1),
			 sizeof(*taint_analysis.registers)
			 );

	if (taint_analysis.registers == NULL)
	{
		fprintf(stderr, "cannot alloc taint_analysis->registers\n");
		exit(EXIT_FAILURE);
	}

	/* Init callback information */
	taint_analysis.callback_info = taint_init_callback_info(nb_registers);

	return taint_analysis;
}

struct taint_callback_info_t *
taint_init_callback_info(uint64_t nb_registers)
{
	struct taint_callback_info_t *callback_info;

	callback_info = malloc(sizeof(*callback_info));
        if (callback_info == NULL)
	{
		fprintf(stderr, "cannot alloc taint_analysis->callback_info\n");
		exit(EXIT_FAILURE);
	}

	/* Registers */
	callback_info->registers
		= calloc((nb_registers/NB_BITS_IN_UINT32_T+1),
			 sizeof(*callback_info->registers)
			 );
        if (callback_info->registers == NULL)
	{
		fprintf(stderr, "cannot alloc callback_info->registers\n");
		exit(EXIT_FAILURE);
	}

	/* Memory */
	callback_info->memory = malloc(sizeof(*callback_info->memory)*NB_MEM_ALLOC_CB);
        if (callback_info->memory == NULL)
	{
		fprintf(stderr, "cannot alloc taint_analysis->callback_info->memory\n");
		exit(EXIT_FAILURE);
	}

	callback_info->allocated = NB_MEM_ALLOC_CB;
	callback_info->nb_mem = 0;

	/* Exceptions for calbacks */
	callback_info->exception_flag = 0;

	return callback_info;
}

void
taint_check_color(uint64_t color_index, uint64_t nb_colors)
{
	if (color_index >= nb_colors)
	{
		fprintf(stderr, "color %" PRIu64 " does not exist\n", color_index);
		exit(EXIT_FAILURE);
	}
}
/* Regsiters */
void
taint_add_register(struct taint_colors_t *colors,
		   uint64_t color_index,
		   uint64_t register_index
		   )
{
	taint_check_color(color_index, colors->nb_colors);
	// TODO: check if register_index < nb_register
	bitfield_set_bit(colors->colors[color_index].registers, register_index);
}

void
taint_remove_register(struct taint_colors_t *colors,
		      uint64_t color_index,
		      uint64_t register_index
		      )
{
	taint_check_color(color_index, colors->nb_colors);
	bitfield_unset_bit(colors->colors[color_index].registers, register_index);
}

int
taint_get_register(struct taint_colors_t *colors,
		   uint64_t color_index,
		   uint64_t register_index
		   )
{
	taint_check_color(color_index, colors->nb_colors);
	return bitfield_test_bit(colors->colors[color_index].registers, register_index);
}

void
taint_color_remove_all_registers(struct taint_colors_t *colors, uint64_t color_index)
{
	taint_check_color(color_index, colors->nb_colors);
	uint64_t i;
	for(i = 0; i < (colors->nb_registers/NB_BITS_IN_UINT32_T + 1); i++)
	{
		colors->colors[color_index].registers[i] = 0;
	}
}

void
taint_remove_all_registers(struct taint_colors_t *colors)
{
	int color_index;
	for (color_index = 0 ; color_index < colors->nb_colors ; color_index++)
	{
		taint_color_remove_all_registers(colors, color_index);
	}
}

void
taint_clean_all_callback_info(struct taint_colors_t *colors)
{
	int color_index;

	for(color_index = 0; color_index < colors->nb_colors ; color_index++)
	{
		taint_clean_callback_info_unsafe(colors, color_index);
	}
}

void
taint_clean_callback_info_unsafe(struct taint_colors_t *colors,
				 uint64_t color_index
				 )
{
	// TODO: Maybe use taint_remove_all_registers
	int i;

	for(i = 0; i < (colors->nb_registers/NB_BITS_IN_UINT32_T + 1); i++)
	{
		colors->colors[color_index].callback_info->registers[i] = 0;
	}

	colors->colors[color_index].callback_info->nb_mem = 0;
}

void
taint_clean_callback_info_safe(struct taint_colors_t *colors,
			       uint64_t color_index
			       )
{
	taint_check_color(color_index, colors->nb_colors);

	int i;

	for(i = 0; i < (colors->nb_registers/NB_BITS_IN_UINT32_T + 1); i++)
	{
		colors->colors[color_index].callback_info->registers[i] = 0;
	}

	colors->colors[color_index].callback_info->nb_mem = 0;
}

void
taint_update_memory_callback_info(struct taint_colors_t *colors,
				  uint64_t color_index,
				  uint64_t addr,
				  uint64_t size
				  )
{
	struct taint_callback_info_t *callback_info;
	callback_info = colors->colors[color_index].callback_info;

	if ( callback_info->nb_mem >= callback_info->allocated )
	{
		callback_info->allocated *= 2;
		callback_info->memory = realloc(callback_info->memory,
						callback_info->allocated
						* sizeof(*callback_info->memory)
						);
	}

	callback_info->memory[callback_info->nb_mem].addr = addr;
	callback_info->memory[callback_info->nb_mem].size = size;
	callback_info->nb_mem += 1;
}

void
taint_add_callback_register(struct taint_colors_t *colors,
			    uint64_t color_index,
			    uint64_t register_index
			    )
{
	taint_check_color(color_index, colors->nb_colors);
	bitfield_set_bit(colors->colors[color_index].callback_info->registers, register_index);
}

/* Memory */
int
taint_generic_access(vm_mngr_t* vm_mngr,
		     uint64_t addr,
		     uint64_t size,
		     int access_type,
		     uint64_t color_index
		     )
{
	struct memory_page_node *mpn;
	mpn = get_memory_page_from_address(vm_mngr, addr, DO_RAISE_EXCEPTION);

	if(!mpn)
		return 0; // Error: Memory not mapped

	/* Fits in one page */
	if (addr - mpn->ad + size <= mpn->size)
	{
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			if (taint_action_on_access(mpn->taint[color_index],
						   (addr + i) - mpn->ad,
						   access_type
						   ))
				return 1;
		}
	}
	/* Multiple pages wide */
	// NOTE: can this be optimized ?
	else
	{
		// ref : miasm2/jitter/vm_mngr.c ligne 248
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			mpn = get_memory_page_from_address(vm_mngr,
							   addr + i,
							   DO_RAISE_EXCEPTION
							   );
			if (!mpn)
				return 0; // Error: Memory not mapped
			if (taint_action_on_access(mpn->taint[color_index],
						   (addr + i) - mpn->ad,
						   access_type
						   ))
				return 1;
		}
	}
	return 0;
}

int
taint_action_on_access(uint32_t *taint, uint64_t index, int access_type)
{
	if (access_type == ADD_MEMORY)
		bitfield_set_bit(taint, index);
	else if (access_type == REMOVE_MEMORY)
		bitfield_unset_bit(taint, index);
	else if (access_type == TEST_MEMORY)
		return bitfield_test_bit(taint, index);
	return 0;
}

void
taint_add_memory(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size, uint64_t color_index)
{
	taint_generic_access(vm_mngr, addr, size, ADD_MEMORY, color_index);
}

void
taint_remove_memory(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size, uint64_t color_index)
{
	taint_generic_access(vm_mngr, addr, size, REMOVE_MEMORY, color_index);
}

int
taint_get_memory(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t size, uint64_t color_index)
{
	return taint_generic_access(vm_mngr, addr, size, TEST_MEMORY, color_index);
}

void
taint_remove_all_memory(vm_mngr_t* vm_mngr)
{
	int i;
	int j;
	int k;
	for (i = 0; i < vm_mngr->memory_pages_number ; i++)
	{
		for ( k = 0; k < vm_mngr->nb_colors ; k++)
		{
			for(j = 0;
			    j < (vm_mngr->memory_pages_array[i].size/NB_BITS_IN_UINT32_T+1);
			    j++)
			{
				vm_mngr->memory_pages_array[i].taint[k][j] = 0;
			}
		}
	}
}

void
taint_color_remove_all_memory(vm_mngr_t* vm_mngr, uint64_t color_index)
{
	int page_number;
	int index;
	for (page_number = 0; page_number < vm_mngr->memory_pages_number ; page_number++)
	{
		for(index = 0;
		    index < (vm_mngr->memory_pages_array[page_number].size/NB_BITS_IN_UINT32_T+1);
		    index++)
		{
			vm_mngr->memory_pages_array[page_number].taint[color_index][index] = 0;
		}
	}
}

void
taint_init_memory(vm_mngr_t* vm_mngr, uint64_t nb_colors)
{
	vm_mngr->do_taint = 1;
	vm_mngr->nb_colors = nb_colors;

	int i;
	for (i = 0; i < vm_mngr->memory_pages_number; i++)
	{
		vm_mngr->memory_pages_array[i].taint =
			malloc(nb_colors*sizeof(*vm_mngr->memory_pages_array[i].taint));

		if (!vm_mngr->memory_pages_array[i].taint)
		{
			fprintf(stderr,
				"cannot alloc vm_mngr->memory_pages_array[%d].taint\n",
				i);
			exit(EXIT_FAILURE);
		}

		uint64_t color_index;
		for (color_index = 0 ; color_index < vm_mngr->nb_colors ; color_index++)
		{
			vm_mngr->memory_pages_array[i].taint[color_index] =
				calloc(vm_mngr->memory_pages_array[i].size/NB_BITS_IN_UINT32_T + 1,
				       sizeof(*vm_mngr->memory_pages_array[i].taint[color_index])
				       );

			if (!vm_mngr->memory_pages_array[i].taint[color_index])
			{
				fprintf(stderr,
					"cannot alloc vm_mngr->memory_pages_array[%d].taint[%" PRIu64  "]\n",
					i,
					color_index
					);
				exit(EXIT_FAILURE);
			}
		}
	}
}

/* Utils */
/* Bit fields */
void
bitfield_set_bit(uint32_t bfield[],  uint64_t index)
{
	bfield[index/NB_BITS_IN_UINT32_T] |= 1 << (index%NB_BITS_IN_UINT32_T);
}

void
bitfield_unset_bit(uint32_t bfield[],  uint64_t index)
{
	bfield[index/NB_BITS_IN_UINT32_T] &= ~(1 << (index%NB_BITS_IN_UINT32_T));
}

int
bitfield_test_bit(uint32_t bfield[],  uint64_t index)
{
	return ( (bfield[index/NB_BITS_IN_UINT32_T] & (1 << (index%NB_BITS_IN_UINT32_T) )) != 0 );
}


/* Python API */
PyObject *
cpu_taint_register(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	PyObject *register_index_py;
	uint64_t color_index;
	uint64_t register_index;

	if (!PyArg_ParseTuple(args, "OO", &color_index_py, &register_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);
	PyGetInt(register_index_py, register_index);

	taint_add_register(self->taint_analysis, color_index, register_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_untaint_register(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	PyObject *register_index_py;
	uint64_t color_index;
	uint64_t register_index;

	if (!PyArg_ParseTuple(args, "OO", &color_index_py, &register_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);
	PyGetInt(register_index_py, register_index);

	taint_remove_register(self->taint_analysis, color_index, register_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_untaint_all_registers(JitCpu* self)
{
	taint_remove_all_registers(self->taint_analysis);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_color_untaint_all_registers(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_color_remove_all_registers(self->taint_analysis, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_taint_memory(JitCpu* self, PyObject* args)
{
	PyObject *addr_py;
	PyObject *size_py;
	PyObject *color_index_py;
	uint64_t addr;
	uint64_t size;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "OOO", &addr_py, &size_py, &color_index_py))
		return NULL;

	PyGetInt(addr_py, addr);
	PyGetInt(size_py, size);
	PyGetInt(color_index_py, color_index);

	taint_add_memory(&self->pyvm->vm_mngr, addr, size, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_untaint_memory(JitCpu* self, PyObject* args)
{
	PyObject *addr_py;
	PyObject *size_py;
	PyObject *color_index_py;
	uint64_t addr;
	uint64_t size;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "OOO", &addr_py, &size_py, &color_index_py))
		return NULL;

	PyGetInt(addr_py, addr);
	PyGetInt(size_py, size);
	PyGetInt(color_index_py, color_index);

	taint_remove_memory(&self->pyvm->vm_mngr, addr, size, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_untaint_all_memory(JitCpu* self)
{
	taint_remove_all_memory(&self->pyvm->vm_mngr);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_color_untaint_all_memory(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_color_remove_all_memory(&self->pyvm->vm_mngr, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_untaint_all(JitCpu* self)
{
	taint_remove_all_registers(self->taint_analysis);
	taint_remove_all_memory(&self->pyvm->vm_mngr);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_color_untaint_all(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_color_remove_all_registers(self->taint_analysis, color_index);
	taint_color_remove_all_memory(&self->pyvm->vm_mngr, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_init_taint(JitCpu* self, PyObject* args)
{
	/* Init colors (registers and callback info) */
	PyObject *nb_regs_py;
	PyObject *nb_colors_py;
	uint64_t nb_regs;
	uint64_t nb_colors;

	if (!PyArg_ParseTuple(args, "OO", &nb_colors_py, &nb_regs_py))
		return NULL;

	PyGetInt(nb_regs_py, nb_regs);
	PyGetInt(nb_colors_py, nb_colors);

	self->taint_analysis = taint_init_colors(nb_colors, nb_regs);

	/* Init memory */
	taint_init_memory(&self->pyvm->vm_mngr, nb_colors);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_get_last_tainted_registers(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);

	uint32_t* last_registers;
	last_registers = self->taint_analysis->colors[color_index].callback_info->registers;

	PyObject *all_regs = PyList_New(0);

	int i;
	for( i = 0; i < self->taint_analysis->nb_registers; i++)
	{
		if ( bitfield_test_bit(last_registers, i) )
		{
			PyList_Append(all_regs,
				       PyInt_FromLong(i)
				       );
		}
	}

	return all_regs;
}

PyObject *
cpu_get_last_tainted_memory(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);

	struct taint_callback_info_t* taint_callback_info;
	taint_callback_info = self->taint_analysis->colors[color_index].callback_info;

	PyObject *tainted_memory = PyList_New(0);

	int i;

	for( i = 0; i < taint_callback_info->nb_mem; i++)
	{
		PyObject *addr;
		PyObject *size;

		addr = PyInt_FromLong(taint_callback_info->memory[i].addr);
		size = PyInt_FromLong(taint_callback_info->memory[i].size);

		PyObject *tuple = PyTuple_New(2);

		PyTuple_SetItem(tuple, 0, addr);
		PyTuple_SetItem(tuple, 1, size);
		PyList_Append(tainted_memory, tuple);
	}

	return tainted_memory;
}

PyObject *
cpu_get_all_taint(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);

	/* Regsiters */
	PyObject *tainted_registers = PyList_New(0);

	int register_index;
	for( register_index = 0; register_index < self->taint_analysis->nb_registers; register_index++)
	{
		if ( taint_get_register(self->taint_analysis, color_index, register_index))
			PyList_Append(tainted_registers,
				       PyInt_FromLong(register_index)
				       );
	}

	/* Memory */
	vm_mngr_t* vm_mngr = &self->pyvm->vm_mngr;
	PyObject *tainted_memory = PyList_New(0);

	PyObject* addr_size;
	uint64_t addr;
	uint64_t size = 0;
	int page_number;
	int i;
	for( page_number = 0; page_number < vm_mngr->memory_pages_number; page_number++)
	{
		for ( i = 0; i < vm_mngr->memory_pages_array[page_number].size; i++)
		{
			if (bitfield_test_bit(vm_mngr->memory_pages_array[page_number].taint[color_index],
					      i))
			{
				if (!size)
				{
					addr = vm_mngr->memory_pages_array[page_number].ad+i;
					size++;
				}
				else
				{
					size++;
				}
			}
			else
			{
				if (size)
				{
					addr_size = PyTuple_New(2);
					PyTuple_SetItem(addr_size,
							0,
							PyInt_FromLong(addr)
							);
					PyTuple_SetItem(addr_size,
							1,
							PyInt_FromLong(size)
							);
					PyList_Append(tainted_memory,
						      addr_size
						      );
					size = 0;
				}
			}
		}
	}

	/* Joining data */
	PyObject *out_obj = PyTuple_New(2);

	PyTuple_SetItem(out_obj, 0, tainted_registers);
	PyTuple_SetItem(out_obj, 1, tainted_memory);

	return out_obj;
}

/* Set or unset exception flags */
PyObject *
cpu_do_taint_reg_cb(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	self->taint_analysis->colors[color_index].callback_info->exception_flag
		^= DO_TAINT_REG_CB;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_do_untaint_reg_cb(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	self->taint_analysis->colors[color_index].callback_info->exception_flag
		^= DO_UNTAINT_REG_CB;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_do_taint_mem_cb(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	self->taint_analysis->colors[color_index].callback_info->exception_flag
		^= DO_TAINT_MEM_CB;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_do_untaint_mem_cb(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	int color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt(color_index_py, color_index);

	self->taint_analysis->colors[color_index].callback_info->exception_flag
		^= DO_UNTAINT_MEM_CB;

	Py_INCREF(Py_None);
	return Py_None;
}
