#include <Python.h>

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../jitter/compat_py23.h"
#include "../jitter/bn.h"
#include "../jitter/queue.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"

#include "taint_analysis.h"

/* Taint setters/getters */
/* Colors */
struct taint_colors_t*
taint_init_colors(uint64_t nb_colors, uint64_t nb_registers, uint32_t max_register_size)
{
	struct taint_colors_t* taint_colors;

	taint_colors = malloc(sizeof(*taint_colors));
	if (taint_colors == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc taint_colors\n");
		exit(EXIT_FAILURE);
	}

	taint_colors->colors = malloc(nb_colors*sizeof(*taint_colors->colors));
	if (taint_colors->colors == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc taint_colors->colors\n");
		exit(EXIT_FAILURE);
	}

	taint_colors->nb_colors = nb_colors;
	taint_colors->nb_registers = nb_registers;
	taint_colors->max_register_size = max_register_size;

	int i;
	for (i = 0 ; i < nb_colors ; i++)
	{
		taint_colors->colors[i] = taint_init_color(nb_registers, max_register_size);
	}

	return taint_colors;
}

struct taint_color_t
taint_init_color(uint64_t nb_registers, uint32_t max_register_size)
{
	struct taint_color_t taint_analysis;

	/* Init registers */
	/* Registers taint information is stored in a bit field. This bit field
	 * contains 8 bits per register (we have a max of 8 bytes per register
	 * by default).
	 */
	taint_analysis.registers
		= calloc(BIT_FIELD_SIZE(nb_registers*max_register_size),
			 sizeof(*taint_analysis.registers)
			 );

	if (taint_analysis.registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc taint_analysis->registers\n");
		exit(EXIT_FAILURE);
	}

	/* Init callback information */
	taint_analysis.callback_info = taint_init_callback_info(nb_registers,
								max_register_size);

	return taint_analysis;
}

void
taint_check_color(uint64_t color_index, uint64_t nb_colors)
{
	if (color_index >= nb_colors)
	{
		fprintf(stderr,
			"TAINT: color %"PRIu64" does not exist\n",
			color_index);
		exit(EXIT_FAILURE);
	}
}

void
taint_check_register(uint64_t register_index,
		     struct taint_interval_t* interval,
		     uint64_t nb_registers,
		     uint32_t max_register_size
		     )
{
	if (register_index >= nb_registers)
	{
		fprintf(stderr,
			"TAINT: register %"PRIu64" does not exist\n",
			register_index);
		exit(EXIT_FAILURE);
	}
	if (interval->start >= max_register_size)
	{
		fprintf(stderr,
			"TAINT: register %"PRIu64" does not have more than "
			"%"PRIu32" bytes.\n You tried to start reading at "
			"byte %"PRIu32"(+1).\n",
			register_index,
			max_register_size,
			interval->start);
		exit(EXIT_FAILURE);
	}
	if (interval->end >= max_register_size)
	{
		fprintf(stderr,
			"TAINT: register %"PRIu64" does not have more than "
			"%"PRIu32" bytes.\n You tried to reading until byte "
			"%"PRIu32" (+1).\n",
			register_index,
			max_register_size,
			interval->end);
		exit(EXIT_FAILURE);
	}
	if (interval->end < interval->start)
	{
		fprintf(stderr,
			"TAINT: register %"PRIu64" -> You tried to reading "
			"from byte %"PRIu32" to byte %"PRIu32"\n",
			register_index,
			interval->start,
			interval->end);
		exit(EXIT_FAILURE);
	}
}

/* Registers */
void
taint_register_generic_access(struct taint_colors_t *colors,
			      uint64_t color_index,
			      uint64_t register_index,
			      struct taint_interval_t* interval,
			      uint32_t access_type
			      )
{
	uint64_t index;
	for (index = interval->start; index <= interval->end ; index++)
		bitfield_generic_access(colors->colors[color_index].registers,
					register_index*colors->max_register_size+index,
					access_type);
}

struct taint_interval_t*
taint_get_register_color(struct taint_colors_t *colors,
			 uint64_t color_index,
			 uint64_t register_index,
			 struct taint_interval_t* interval
			 )
{
	return taint_get_register(colors->colors[color_index].registers,
				  register_index,
				  interval,
				  colors->max_register_size);
}

struct taint_interval_t*
taint_get_register(uint32_t* registers,
		   uint64_t register_index,
		   struct taint_interval_t* interval,
		   uint32_t max_register_size
		   )
{
	struct taint_interval_t* tainted_interval;
	tainted_interval = malloc(sizeof(*tainted_interval));
        if (tainted_interval == NULL)
	{
		fprintf(stderr,
			"TAINT: cannot alloc tainted_interval in "
			"taint_get_register()\n");
		exit(EXIT_FAILURE);
	}
	tainted_interval->start = -1;

	uint64_t index;
	for (index = interval->start; index <= interval->end ; index++)
	{
		if (bitfield_test_bit(registers, register_index*max_register_size+index))
		{
			if (tainted_interval->start == -1)
			{
				tainted_interval->start = index;
				tainted_interval->end = index;
			}
			else
			{
				if (tainted_interval->end+1 != index)
				{
					fprintf(stderr,
						"TAINT:DEBUG espace dans "
						"registre non contigue\n");
					exit(EXIT_FAILURE);
				}
				tainted_interval->end = index;
			}
		}
	}

	if (tainted_interval->start == -1)
	{
		// No taint
		free(tainted_interval);
		return NULL;
	}
	return tainted_interval;
}
void
taint_color_remove_all_registers(struct taint_colors_t *colors, uint64_t color_index)
{
	uint64_t i;
	for(i = 0;
	    i < BIT_FIELD_SIZE(colors->nb_registers*colors->max_register_size);
	    i++)
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



/* Memory */
void
taint_memory_generic_access(vm_mngr_t* vm_mngr,
			    uint64_t addr,
			    uint64_t size,
			    uint32_t access_type,
			    uint64_t color_index
			    )
{
	struct memory_page_node *mpn;
	mpn = get_memory_page_from_address(vm_mngr, addr, DO_RAISE_EXCEPTION);

	if(!mpn)
	{
		fprintf(stderr, "TAINT: address %"PRIu64" is not mapped\n", addr);
		return;
	}

	/* Fits in one page */
	if (addr - mpn->ad + size <= mpn->size)
	{
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			bitfield_generic_access(mpn->taint[color_index],
					       (addr + i) - mpn->ad,
					       access_type);
		}
	}
	/* Multiple pages wide */
	// NOTE: can this be optimized ?
	else
	{
		// ref : miasm/jitter/vm_mngr.c ligne 248
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			mpn = get_memory_page_from_address(vm_mngr,
							   addr + i,
							   DO_RAISE_EXCEPTION
							   );
			if (!mpn)
			{
				fprintf(stderr,
					"TAINT: address %"PRIu64" is not "
					"mapped\n",
					addr + i);
				return;
			}
			bitfield_generic_access(mpn->taint[color_index],
					       (addr + i) - mpn->ad,
					       access_type);
		}
	}
}

struct taint_interval_t*
taint_get_memory(vm_mngr_t* vm_mngr,
		 uint64_t addr,
		 uint64_t size,
		 uint64_t color_index
		 )
{
	struct memory_page_node *mpn;
	mpn = get_memory_page_from_address(vm_mngr, addr, DO_RAISE_EXCEPTION);

	if(!mpn)
	{
		fprintf(stderr,
			"TAINT: address %"PRIu64" is not mapped\n",
			addr);
		return NULL;
	}

	struct taint_interval_t* tainted_interval;
	tainted_interval = malloc(sizeof(*tainted_interval));
        if (tainted_interval == NULL)
	{
		fprintf(stderr,
			"TAINT: cannot alloc tainted_interval in "
			"taint_get_memory()\n");
		exit(EXIT_FAILURE);
	}

	tainted_interval->start = -1;

	/* Fits in one page */
	if (addr - mpn->ad + size <= mpn->size)
	{
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			if (bitfield_test_bit(mpn->taint[color_index],
					      (addr + i) - mpn->ad))
			{

				if (tainted_interval->start == -1)
				{
					tainted_interval->start = i;
					tainted_interval->end = i;
				}
				else
				{
					if (tainted_interval->end+1 != i)
					{
						fprintf(stderr,
							"TAINT:DEBUG espace "
							"teinté dans mémoire "
							"non contigue\n");
						exit(EXIT_FAILURE);
					}
					tainted_interval->end = i;
				}
			}
		}
	}
	/* Multiple pages wide */
	// NOTE: can this be optimized ?
	else
	{
		// ref : miasm/jitter/vm_mngr.c ligne 248
		uint64_t i;
		for (i = 0 ; i < size ; i++)
		{
			mpn = get_memory_page_from_address(vm_mngr,
							   addr + i,
							   DO_RAISE_EXCEPTION
							   );
			if (!mpn)
			{
				fprintf(stderr,
					"TAINT: address %"PRIu64" is not"
					"mapped\n",
					addr + i);
				free(tainted_interval);
				return NULL;
			}
			if (bitfield_test_bit(mpn->taint[color_index],
					      (addr + i) - mpn->ad))
				if (tainted_interval->start == -1)
				{
					tainted_interval->start = i;
					tainted_interval->end = i;
				}
				else
				{
					if (tainted_interval->end+1 != i)
					{
						fprintf(stderr,
							"TAINT:DEBUG espace "
							"teinté dans mémoire "
							"non contigue\n");
						exit(EXIT_FAILURE);
					}
					tainted_interval->end = i;
				}

		}
	}
	if (tainted_interval->start == -1)
	{
		// No taint
		free(tainted_interval);
		return NULL;
	}
	return tainted_interval;
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
			    j < BIT_FIELD_SIZE(vm_mngr->memory_pages_array[i].size);
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
		    index < BIT_FIELD_SIZE(vm_mngr->memory_pages_array[page_number].size);
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
				"TAINT: cannot alloc "
				"vm_mngr->memory_pages_array[%d].taint\n",
				i);
			exit(EXIT_FAILURE);
		}

		uint64_t color_index;
		for (color_index = 0 ;
		     color_index < vm_mngr->nb_colors ;
		     color_index++)
		{
			vm_mngr->memory_pages_array[i].taint[color_index] =
				calloc(BIT_FIELD_SIZE(vm_mngr->memory_pages_array[i].size),
				       sizeof(*vm_mngr->memory_pages_array[i].taint[color_index])
				       );

			if (!vm_mngr->memory_pages_array[i].taint[color_index])
			{
				fprintf(stderr,
					"TAINT: cannot alloc "
					"vm_mngr->memory_pages_array[%d].taint"
					"[%"PRIu64"]\n",
					i,
					color_index
					);
				exit(EXIT_FAILURE);
			}
		}
	}
}

/* Callback info */
struct taint_callback_info_t *
taint_init_callback_info(uint64_t nb_registers, uint32_t max_register_size)
{
	struct taint_callback_info_t *callback_info;

	callback_info = malloc(sizeof(*callback_info));
        if (callback_info == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"taint_analysis->callback_info\n");
		exit(EXIT_FAILURE);
	}

	/* last tainted */
	/* Registers */
	callback_info->last_tainted.registers
		= calloc(BIT_FIELD_SIZE(nb_registers*max_register_size),
			 sizeof(*callback_info->last_tainted.registers)
			 );
        if (callback_info->last_tainted.registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"callback_info->last_tainted.registers\n");
		exit(EXIT_FAILURE);
	}

	/* Memory */
	callback_info->last_tainted.memory
		= malloc(sizeof(*callback_info->last_tainted.memory)*NB_MEM_ALLOC_CB);
        if (callback_info->last_tainted.memory == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"taint_analysis->callback_info->"
				"last_tainted.memory\n");
		exit(EXIT_FAILURE);
	}

	callback_info->last_tainted.allocated = NB_MEM_ALLOC_CB;
	callback_info->last_tainted.nb_mem = 0;

	/* last untainted */
	/* Registers */
	callback_info->last_untainted.registers
		= calloc(BIT_FIELD_SIZE(nb_registers*max_register_size),
			 sizeof(*callback_info->last_untainted.registers)
			 );
        if (callback_info->last_untainted.registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"callback_info->last_untainted.registers\n");
		exit(EXIT_FAILURE);
	}

	/* Memory */
	callback_info->last_untainted.memory
		= malloc(sizeof(*callback_info->last_untainted.memory)*NB_MEM_ALLOC_CB);
        if (callback_info->last_untainted.memory == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"taint_analysis->callback_info->"
				"last_untainted.memory\n");
		exit(EXIT_FAILURE);
	}

	callback_info->last_untainted.allocated = NB_MEM_ALLOC_CB;
	callback_info->last_untainted.nb_mem = 0;

	/* Exceptions for calbacks */
	callback_info->exception_flag = 0;

	return callback_info;
}

void
taint_clean_all_callback_info(struct taint_colors_t *colors)
{
	int color_index;

	for(color_index = 0; color_index < colors->nb_colors ; color_index++)
	{
		taint_clean_callback_info(colors, color_index);
	}
}

void
taint_clean_callback_info(struct taint_colors_t *colors,
			  uint64_t color_index
			  )
{
	int i;

	for(i = 0;
	    i < BIT_FIELD_SIZE(colors->nb_registers*colors->max_register_size)
	    ; i++)
	{
		colors->colors[color_index].callback_info->
			last_tainted.registers[i] = 0;
		colors->colors[color_index].callback_info->
			last_untainted.registers[i] = 0;
	}

	colors->colors[color_index].callback_info->last_tainted.nb_mem = 0;
	colors->colors[color_index].callback_info->last_untainted.nb_mem = 0;
}

void
taint_update_memory_callback_info(struct taint_colors_t *colors,
				  uint64_t color_index,
				  uint64_t addr,
				  uint64_t size,
				  int event_type
				  )
{
	struct taint_last_modify_t* last_modify;
	if (event_type == TAINT_EVENT)
	{
		last_modify = &(colors->colors[color_index].callback_info->
				last_tainted);
	}
	else if (event_type == UNTAINT_EVENT)
	{
		last_modify = &(colors->colors[color_index].callback_info->
				last_untainted);
	}
	else
	{
		fprintf(stderr,
			"TAINT: unknown event type %d\n"
			"\t-> Callback information are not updated !\n",
			event_type);
		return;
	}

	if ( last_modify->nb_mem >= last_modify->allocated )
	{
		last_modify->allocated *= 2;
		last_modify->memory = realloc(last_modify->memory,
						last_modify->allocated
						* sizeof(*last_modify->memory)
						);
	}

	last_modify->memory[last_modify->nb_mem].addr = addr;
	last_modify->memory[last_modify->nb_mem].size = size;
	last_modify->nb_mem += 1;
}

void
taint_update_register_callback_info(struct taint_colors_t *colors,
				    uint64_t color_index,
				    uint64_t register_index,
				    struct taint_interval_t* interval,
				    int event_type
				    )
{
	if (event_type == TAINT_EVENT)
	{

		uint64_t index;
		for (index = interval->start;
		     index <= interval->end;
		     index++)
			bitfield_set_bit(colors->colors[color_index].
						callback_info->
						last_tainted.registers,
					 register_index*colors->
						max_register_size+index);
	}
	else if (event_type == UNTAINT_EVENT)
	{
		uint64_t index;
		for (index = interval->start;
		     index <= interval->end;
		     index++)
			bitfield_set_bit(colors->colors[color_index].
						callback_info->
						last_untainted.registers,
					 register_index*colors->
						max_register_size+index);
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

void
bitfield_generic_access(uint32_t *bitfield, uint64_t index, uint32_t access_type)
{
	if (access_type == ADD)
		bitfield_set_bit(bitfield, index);
	else if (access_type == REMOVE)
		bitfield_unset_bit(bitfield, index);
}

int
bitfield_test_bit(uint32_t bfield[],  uint64_t index)
{
	return ( (bfield[index/NB_BITS_IN_UINT32_T] & (1 << (index%NB_BITS_IN_UINT32_T) )) != 0 );
}



/* Python API */
PyObject*
cpu_access_register(JitCpu* cpu, PyObject* args, uint32_t access_type)
{
	PyObject *color_index_py;
	PyObject *register_index_py;
	PyObject *start_py;
	start_py = PyInt_FromLong(DEFAULT_REG_START);
	PyObject *end_py;
	end_py = PyInt_FromLong(cpu->taint_analysis->max_register_size-1);
	uint64_t color_index;
	uint64_t register_index;
	uint64_t start;
	uint64_t end;

	if (!PyArg_ParseTuple(args,
			      "OO|OO",
			      &color_index_py,
			      &register_index_py,
			      &start_py,
			      &end_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);
	PyGetInt_uint64_t(register_index_py, register_index);
	PyGetInt_uint64_t(start_py, start);
	PyGetInt_uint64_t(end_py, end);

	struct taint_interval_t* interval;
	interval = malloc(sizeof(*interval));
	interval->start = start;
	interval->end = end;

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);
	taint_check_register(register_index,
			     interval,
			     cpu->taint_analysis->nb_registers,
			     cpu->taint_analysis->max_register_size);
	taint_register_generic_access(cpu->taint_analysis,
				      color_index,
				      register_index,
				      interval,
				      access_type);

	free(interval);
	Py_INCREF(Py_None);
	return Py_None;

}
PyObject*
cpu_taint_register(JitCpu* self, PyObject* args)
{
	return cpu_access_register(self, args, ADD);
}

PyObject*
cpu_untaint_register(JitCpu* self, PyObject* args)
{
	return cpu_access_register(self, args, REMOVE);
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

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);
	taint_color_remove_all_registers(self->taint_analysis, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_access_memory(JitCpu* cpu, PyObject* args, uint32_t access_type)
{
	PyObject *addr_py;
	PyObject *size_py;
	PyObject *color_index_py;
	uint64_t addr;
	uint64_t size;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "OOO", &addr_py, &size_py, &color_index_py))
		return NULL;

	PyGetInt_uint64_t(addr_py, addr);
	PyGetInt_uint64_t(size_py, size);
	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);
	taint_memory_generic_access(&cpu->pyvm->vm_mngr, addr, size, access_type, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_taint_memory(JitCpu* self, PyObject* args)
{
	return cpu_access_memory(self, args, ADD);
}

PyObject *
cpu_untaint_memory(JitCpu* self, PyObject* args)
{
	return cpu_access_memory(self, args, REMOVE);
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

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);
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

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);
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
	PyObject *max_register_size_py;
	/* REF: docs.python.org
	 * 'C variables corresponding to optional arguments [...]
	 * PyArg_ParseTuple() does not touch the contents of the corresponding C
	 * variables.'
	 * -> That why we initialize it to the default value.
	 */
	max_register_size_py = PyInt_FromLong(DEFAULT_MAX_REG_SIZE);

	uint64_t nb_regs;
	uint64_t nb_colors;
	uint32_t max_register_size;

	if (!PyArg_ParseTuple(args,
			      "OO|O",
			      &nb_colors_py,
			      &nb_regs_py,
			      &max_register_size_py))
		return NULL;

	PyGetInt_uint64_t(nb_regs_py, nb_regs);
	PyGetInt_uint64_t(nb_colors_py, nb_colors);
	PyGetInt_uint64_t(max_register_size_py, max_register_size);

	self->taint_analysis = taint_init_colors(nb_colors,
						 nb_regs,
						 max_register_size);

	/* Init memory */
	taint_init_memory(&self->pyvm->vm_mngr, nb_colors);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_get_registers(uint32_t* registers,
		  uint64_t nb_registers,
		  uint32_t max_register_size
		  )
{
	PyObject *tainted_registers = PyList_New(0);
	struct taint_interval_t* interval;
	struct taint_interval_t* interval_arg;
	interval_arg = malloc(sizeof(*interval_arg));
	interval_arg->start = DEFAULT_REG_START;
	interval_arg->end = DEFAULT_MAX_REG_SIZE-1;

	int register_index;
	for( register_index = 0; register_index < nb_registers; register_index++)
	{
		interval = taint_get_register(registers,
						register_index,
						interval_arg,
						max_register_size);
		if (interval != NULL)
		{
			PyObject *register_index_py;
			PyObject *start;
			PyObject *end;

			register_index_py = PyInt_FromLong(register_index);
			start = PyInt_FromLong(interval->start);
			end = PyInt_FromLong(interval->end);

			PyObject *tuple = PyTuple_New(3);

			PyTuple_SetItem(tuple, 0, register_index_py);
			PyTuple_SetItem(tuple, 1, start);
			PyTuple_SetItem(tuple, 2, end);
			PyList_Append(tainted_registers, tuple);
		}
	}

	free(interval_arg);
	return tainted_registers;
}

PyObject *
cpu_get_last_register(JitCpu* cpu, PyObject* args, uint32_t event_type)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);

	uint32_t* registers;
	if (event_type == TAINT_EVENT)
		registers = cpu->taint_analysis->colors[color_index]
			.callback_info->last_tainted.registers;
	else
		registers = cpu->taint_analysis->colors[color_index]
			.callback_info->last_untainted.registers;

	return cpu_get_registers(registers,
				 cpu->taint_analysis->nb_registers,
				 cpu->taint_analysis->max_register_size);
}

PyObject*
cpu_get_last_tainted_registers(JitCpu* self, PyObject* args)
{
	return cpu_get_last_register(self, args, TAINT_EVENT);
}

PyObject *
cpu_get_last_untainted_registers(JitCpu* self, PyObject* args)
{
	return cpu_get_last_register(self, args, UNTAINT_EVENT);
}

PyObject*
cpu_get_memory(vm_mngr_t* vm_mngr, uint64_t color_index)
{
	PyObject *tainted_memory = PyList_New(0);

	PyObject* addr_size;
	uint64_t addr;
	uint64_t size = 0;
	int page_number;
	int i;
	for( page_number = 0;
	     page_number < vm_mngr->memory_pages_number;
	     page_number++)
	{
		for ( i = 0;
		      i < vm_mngr->memory_pages_array[page_number].size;
		      i++)
		{
			if (bitfield_test_bit(vm_mngr->
						memory_pages_array[page_number].
						taint[color_index],
					      i))
			{
				if (!size)
				{
					addr = vm_mngr->
						memory_pages_array[page_number].
						ad+i;
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
							PyLong_FromUnsignedLongLong(addr)
							);
					PyTuple_SetItem(addr_size,
							1,
							PyLong_FromUnsignedLongLong(size)
							);
					PyList_Append(tainted_memory,
						      addr_size
						      );
					size = 0;
				}
			}
		}
	}

	return tainted_memory;
}

PyObject *
cpu_get_last_memory(JitCpu* cpu, PyObject* args, uint32_t event_type)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);

	struct taint_last_modify_t last_modify;
	if (event_type == TAINT_EVENT)
		last_modify =
			cpu->taint_analysis->colors[color_index].callback_info->last_tainted;
	else
		last_modify =
			cpu->taint_analysis->colors[color_index].callback_info->last_untainted;

	PyObject *modified_memory = PyList_New(0);

	int i;

	for( i = 0; i < last_modify.nb_mem; i++)
	{
		PyObject *addr;
		PyObject *size;

		addr = PyLong_FromUnsignedLongLong(last_modify.memory[i].addr);
		size = PyLong_FromUnsignedLongLong(last_modify.memory[i].size);

		PyObject *tuple = PyTuple_New(2);

		PyTuple_SetItem(tuple, 0, addr);
		PyTuple_SetItem(tuple, 1, size);
		PyList_Append(modified_memory, tuple);
	}

	return modified_memory;
}

PyObject *
cpu_get_last_tainted_memory(JitCpu* self, PyObject* args)
{
	return cpu_get_last_memory(self, args, TAINT_EVENT);
}

PyObject *
cpu_get_last_untainted_memory(JitCpu* self, PyObject* args)
{
	return cpu_get_last_memory(self, args, UNTAINT_EVENT);
}

PyObject *
cpu_get_all_taint(JitCpu* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint_analysis->nb_colors);

	/* Registers */
	PyObject *tainted_registers
		= cpu_get_registers(self->taint_analysis->colors[color_index].registers,
				    self->taint_analysis->nb_registers,
				    self->taint_analysis->max_register_size);

	/* Memory */
	PyObject *tainted_memory = cpu_get_memory(&self->pyvm->vm_mngr, color_index);

	/* Joining data */
	PyObject *out_obj = PyTuple_New(2);

	PyTuple_SetItem(out_obj, 0, tainted_registers);
	PyTuple_SetItem(out_obj, 1, tainted_memory);

	return out_obj;
}

/* Set or unset exception flags */
PyObject *
cpu_enable_cb(JitCpu* cpu, PyObject* args, uint32_t cb)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);

	cpu->taint_analysis->colors[color_index].callback_info->exception_flag
		|= cb;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_enable_taint_reg_cb(JitCpu* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_TAINT_REG_CB);
}

PyObject *
cpu_enable_untaint_reg_cb(JitCpu* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_UNTAINT_REG_CB);
}

PyObject *
cpu_enable_taint_mem_cb(JitCpu* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_TAINT_MEM_CB);
}

PyObject *
cpu_enable_untaint_mem_cb(JitCpu* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_UNTAINT_MEM_CB);
}

PyObject *
cpu_disable_cb(JitCpu* cpu, PyObject* args, uint32_t cb)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, cpu->taint_analysis->nb_colors);

	cpu->taint_analysis->colors[color_index].callback_info->exception_flag
		&= ~cb;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_disable_taint_reg_cb(JitCpu* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_TAINT_REG_CB);
}

PyObject *
cpu_disable_untaint_reg_cb(JitCpu* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_UNTAINT_REG_CB);
}

PyObject *
cpu_disable_taint_mem_cb(JitCpu* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_TAINT_MEM_CB);
}

PyObject *
cpu_disable_untaint_mem_cb(JitCpu* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_UNTAINT_MEM_CB);
}
