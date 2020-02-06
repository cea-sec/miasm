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
#include "../jitter/interval_tree/interval_tree.h"

#include "taint_analysis.h"


struct rb_root*
taint_get_tainted(struct taint_colors_t *colors,
                  uint64_t color_index,
                  struct taint_reg_list_t *registers,
                  struct taint_reg_list_t *reg_addresses,
                  struct taint_mem_list_t *mem_addresses,
                  struct taint_custom_list_t *memories)
{
    // WIP
    struct rb_root* tainted_interval_tree = interval_tree_new();


    //struct taint_reg_list_t cur_register = *registers;

    //while(cur_register)
    //{
    //    interval_tree_add(tainted_interval_tree,
    //                      taint_get_register_color(colors,
    //                                               color_index,
    //                                               cur_register.id,
    //                                               cur_register.interval)); 
    //    cur_register = cur_register.next;
    //}

    return tainted_interval_tree;
}


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

	uint64_t i;
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

    taint_color_init_registers(&taint_analysis, nb_registers);
    taint_color_init_memory(&taint_analysis);

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
			"byte %"PRIu64"(+1).\n",
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
			"%"PRIu64" (+1).\n",
			register_index,
			max_register_size,
			interval->end);
		exit(EXIT_FAILURE);
	}
	if (interval->end < interval->start)
	{
		fprintf(stderr,
			"TAINT: register %"PRIu64" -> You tried to read "
			"from byte %"PRIu64" to byte %"PRIu64"\n",
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
	if (access_type == ADD)
        interval_tree_add(interval->start,
                          interval->end,
                          colors->colors[color_index].registers[register_index]);
	else if (access_type == REMOVE)
        interval_tree_sub(interval->start,
                          interval->end,
                          colors->colors[color_index].registers[register_index]);
}

struct rb_root*
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

struct rb_root*
taint_get_register(struct rb_root ** registers,
		   uint64_t register_index,
		   struct taint_interval_t* interval,
		   uint32_t max_register_size
		   )
{
    struct rb_root *tainted_interval_tree;

    tainted_interval_tree = interval_tree_intersection(interval->start,
                                                       interval->end,
                                                       registers[register_index]);

	return tainted_interval_tree;
}

void
taint_color_init_registers(struct taint_color_t *color, uint64_t nb_registers)
{
	color->registers
		= calloc(nb_registers, sizeof(*color->registers));

	if (color->registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc color->registers\n");
		exit(EXIT_FAILURE);
	}


	uint64_t i;
	for(i = 0; i < nb_registers; i++)
	{
		color->registers[i] = calloc(1, sizeof(*color->registers[i]));
        if (color->registers[i] == NULL)
        {
            fprintf(stderr, "TAINT: cannot alloc color->registers[i]\n");
            exit(EXIT_FAILURE);
        }
	}
}

void
taint_color_init_memory(struct taint_color_t *color)
{
	color->memory = calloc(1, sizeof(*color->memory));

	if (color->memory == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc color->memory\n");
		exit(EXIT_FAILURE);
	}
}

void
taint_color_remove_all_registers(struct taint_colors_t *colors, uint64_t color_index)
{
	uint64_t i;
	for(i = 0; i < colors->nb_registers; i++)
    {
        interval_tree_free(colors->colors[color_index].registers[i]);
        colors->colors[color_index].registers[i] = interval_tree_new();
    }
}

void
taint_remove_all_registers(struct taint_colors_t *colors)
{
       uint64_t color_index;
       for (color_index = 0 ; color_index < colors->nb_colors ; color_index++)
       {
               taint_color_remove_all_registers(colors, color_index);
       }
}

/* Memory */
void
taint_memory_generic_access(struct taint_colors_t *colors,
                uint64_t color_index,
                struct taint_interval_t* interval,
                           uint32_t access_type
                           )
{
       if (access_type == ADD)
        interval_tree_add(interval->start,
                          interval->end,
                          colors->colors[color_index].memory);
       else if (access_type == REMOVE)
        interval_tree_sub(interval->start,
                          interval->end,
                          colors->colors[color_index].memory);
}

struct rb_root*
taint_get_memory(struct taint_colors_t *colors,
                 uint64_t color_index,
                 struct taint_interval_t* interval)
{
    struct rb_root *tainted_interval_tree;

    tainted_interval_tree = interval_tree_intersection(interval->start,
                                                       interval->end,
                                                       colors->colors[color_index].memory);

       return tainted_interval_tree;
}

void
taint_remove_all_memory(struct taint_colors_t *colors)
{
    for (uint64_t i = 0; i < colors->nb_colors ; i++)
        taint_color_remove_all_memory(colors, i);
}

void
taint_color_remove_all_memory(struct taint_colors_t *colors, uint64_t color_index)
{
    interval_tree_free(colors->colors[color_index].memory);
    colors->colors[color_index].memory = interval_tree_new();
}


/* Callback info */
struct taint_callback_info_t *
taint_init_callback_info(uint64_t nb_registers, uint32_t max_register_size)
{
    // TODO
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
		= calloc(nb_registers, sizeof(*callback_info->last_tainted.registers));

    if (callback_info->last_tainted.registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"callback_info->last_tainted.registers\n");
		exit(EXIT_FAILURE);
	}

    for( uint64_t index = 0; index < nb_registers; index ++)
    {
        callback_info->last_tainted.registers[index] = interval_tree_new();
    }

	/* Memory */
	callback_info->last_tainted.memory = interval_tree_new();

	/* last untainted */
	/* Registers */
	callback_info->last_untainted.registers
		= calloc(nb_registers, sizeof(*callback_info->last_untainted.registers));

    if (callback_info->last_untainted.registers == NULL)
	{
		fprintf(stderr, "TAINT: cannot alloc "
				"callback_info->last_untainted.registers\n");
		exit(EXIT_FAILURE);
	}

    for( uint64_t index = 0; index < nb_registers; index ++)
    {
        callback_info->last_untainted.registers[index] = interval_tree_new();
    }

	/* Memory */
	callback_info->last_untainted.memory = interval_tree_new();

	/* Exceptions for calbacks */
	callback_info->exception_flag = 0;

	return callback_info;
}

void
taint_clean_all_callback_info(struct taint_colors_t *colors)
{
	uint64_t color_index;

	for(color_index = 0; color_index < colors->nb_colors ; color_index++)
	{
		taint_clean_callback_info(colors, color_index);
	}
}

void
taint_clean_callback_info(struct taint_colors_t *colors, uint64_t color_index)
{
	for(uint64_t i = 0; i < colors->nb_registers ; i++)
	{
        interval_tree_free(colors->colors[color_index].callback_info->last_tainted.registers[i]);
        colors->colors[color_index].callback_info->last_tainted.registers[i] = interval_tree_new();
        interval_tree_free(colors->colors[color_index].callback_info->last_untainted.registers[i]);
        colors->colors[color_index].callback_info->last_untainted.registers[i] = interval_tree_new();
	}
    interval_tree_free(colors->colors[color_index].callback_info->last_tainted.memory);
    colors->colors[color_index].callback_info->last_tainted.memory = interval_tree_new();
    interval_tree_free(colors->colors[color_index].callback_info->last_untainted.memory);
    colors->colors[color_index].callback_info->last_untainted.memory = interval_tree_new();
}

void
taint_update_memory_callback_info(struct taint_colors_t *colors,
				  uint64_t color_index,
				  struct taint_interval_t* interval,
				  int event_type
				  )
{
	if (event_type == TAINT_EVENT)
        interval_tree_add(interval->start,
                          interval->end,
		                  colors->colors[color_index].callback_info->last_tainted.memory);
	else if (event_type == UNTAINT_EVENT)
        interval_tree_add(interval->start,
                          interval->end,
		                  colors->colors[color_index].callback_info->last_untainted.memory);
	else
	{
		fprintf(stderr,
			"TAINT: unknown event type %d\n"
			"\t-> Callback information are not updated !\n",
			event_type);
	}
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
        interval_tree_add(interval->start,
                          interval->end,
                          colors->colors[color_index].callback_info->last_tainted.registers[register_index]);
	else if (event_type == UNTAINT_EVENT)
        interval_tree_add(interval->start,
                          interval->end,
                          colors->colors[color_index].callback_info->last_untainted.registers[register_index]);
}


/* Python API */
PyObject*
cpu_access_register(JitCpu* cpu, PyObject* args, uint32_t access_type)
{
	PyObject *color_index_py;
	PyObject *register_index_py;
	PyObject *start_py;
	start_py = PyLong_FromLong(DEFAULT_REG_START);
	PyObject *end_py;
	end_py = PyLong_FromLong(cpu->taint_analysis->max_register_size-1);
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
	struct taint_interval_t* interval_arg;

	if (!PyArg_ParseTuple(args, "OOO", &addr_py, &size_py, &color_index_py))
		return NULL;

	PyGetInt_uint64_t(addr_py, addr);
	PyGetInt_uint64_t(size_py, size);
	PyGetInt_uint64_t(color_index_py, color_index);

    if (size > 0)
    {
	    interval_arg = malloc(sizeof(*interval_arg));
	    interval_arg->start = addr;
	    interval_arg->end = addr + (size - 1);

	    taint_check_color(color_index, cpu->taint_analysis->nb_colors);
	    taint_memory_generic_access(cpu->taint_analysis, color_index, interval_arg, access_type);
    }

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
	taint_remove_all_memory(self->taint_analysis);

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
	taint_color_remove_all_memory(self->taint_analysis, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_untaint_all(JitCpu* self)
{
	taint_remove_all_registers(self->taint_analysis);
	taint_remove_all_memory(self->taint_analysis);

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
	taint_color_remove_all_memory(self->taint_analysis, color_index);

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
	max_register_size_py = PyLong_FromLong(DEFAULT_MAX_REG_SIZE);

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

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_get_registers(struct rb_root ** registers,
		  uint64_t nb_registers,
		  uint32_t max_register_size
		  )
{
	PyObject *tainted_registers = PyList_New(0);
    PyObject *tainted_interval_list, *tuple, *register_index_py, *start, *end;
	struct rb_root* tainted_interval_tree;
    struct rb_node *rb_node;
	struct taint_interval_t* interval_arg;
    struct interval_tree_node *node;
	uint64_t register_index;

	interval_arg = malloc(sizeof(*interval_arg));
	interval_arg->start = DEFAULT_REG_START;
	interval_arg->end = DEFAULT_MAX_REG_SIZE-1;

	for(register_index = 0; register_index < nb_registers; register_index++)
	{
		tainted_interval_tree = taint_get_register(registers,
						register_index,
						interval_arg,
						max_register_size);

		if (tainted_interval_tree != NULL)
		{
            tainted_interval_list = PyList_New(0);
            register_index_py = PyLong_FromLong(register_index);

            rb_node = rb_first(tainted_interval_tree);

            if (rb_node == NULL)
            {
                continue;
            }

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                start = PyLong_FromLong(node->start);
                end = PyLong_FromLong(node->last);

                tuple = PyTuple_New(2);
                PyTuple_SetItem(tuple, 0, start);
                PyTuple_SetItem(tuple, 1, end);
                PyList_Append(tainted_interval_list, tuple);

                rb_node = rb_next(rb_node);
            }
            tuple = PyTuple_New(2);
            PyTuple_SetItem(tuple, 0, register_index_py);
            PyTuple_SetItem(tuple, 1, tainted_interval_list);
            PyList_Append(tainted_registers, tuple);
		}
        free(tainted_interval_tree);
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

	struct rb_root ** registers;
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
cpu_get_memory(struct rb_root * memory)
{
	PyObject *tainted_memory = PyList_New(0);
    PyObject *tuple, *start, *end;
    struct rb_node *rb_node;
    struct interval_tree_node *node;


    rb_node = rb_first(memory);

    while(rb_node != NULL)
    {
        node = rb_entry(rb_node, struct interval_tree_node, rb);
        start = PyLong_FromLong(node->start);
        end = PyLong_FromLong(node->last);

        tuple = PyTuple_New(2);
        PyTuple_SetItem(tuple, 0, start);
        PyTuple_SetItem(tuple, 1, end);
        PyList_Append(tainted_memory, tuple);

        rb_node = rb_next(rb_node);
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

	struct rb_root * memory;
	if (event_type == TAINT_EVENT)
		memory = cpu->taint_analysis->colors[color_index].callback_info->last_tainted.memory;
	else
		memory = cpu->taint_analysis->colors[color_index].callback_info->last_untainted.memory;

	return cpu_get_memory(memory);
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
	PyObject *tainted_memory = cpu_get_memory(self->taint_analysis->colors[color_index].memory);

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
