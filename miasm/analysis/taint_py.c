#include <Python.h>
#include "structmember.h"
#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#include "../jitter/compat_py23.h"
#include "../jitter/queue.h"
#include "../jitter/bn.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"
#include "taint.h"
#include "taint_py.h"


#define PYTHON_CLASS_NAME "TaintMngr"

PyObject*
cpu_access_register(PyTaint* self, PyObject* args, uint32_t access_type)
{
	PyObject *color_index_py;
	PyObject *register_index_py;
	PyObject *start_py;
	start_py = PyLong_FromLong(DEFAULT_REG_START);
	PyObject *end_py;
	end_py = PyLong_FromLong(self->taint->max_register_size-1);
	uint64_t color_index;
	uint64_t register_index;
	uint64_t start;
	uint64_t end;
	struct interval interval;

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

	interval.start = start;
	interval.last = end;

	taint_check_color(color_index, self->taint->nb_colors);
	taint_check_register(register_index,
                         interval,
                         self->taint->nb_registers,
                         self->taint->max_register_size);
	taint_register_generic_access(self->taint,
				      color_index,
				      register_index,
				      interval,
				      access_type);

	Py_INCREF(Py_None);
	return Py_None;

}
PyObject*
cpu_taint_register(PyTaint* self, PyObject* args)
{
	return cpu_access_register(self, args, ADD);
}

PyObject*
cpu_untaint_register(PyTaint* self, PyObject* args)
{
	return cpu_access_register(self, args, REMOVE);
}

PyObject*
cpu_untaint_all_registers(PyTaint* self)
{
	taint_remove_all_registers(self->taint);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_color_untaint_all_registers(PyTaint* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);
	taint_color_remove_all_registers(self->taint, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_access_memory(PyTaint* self, PyObject* args, uint32_t access_type)
{
	PyObject *addr_py;
	PyObject *size_py;
	PyObject *color_index_py;
	uint64_t addr;
	uint64_t size;
	uint64_t color_index;
	struct interval interval_arg;

	if (!PyArg_ParseTuple(args, "OOO", &addr_py, &size_py, &color_index_py))
		return NULL;

	PyGetInt_uint64_t(addr_py, addr);
	PyGetInt_uint64_t(size_py, size);
	PyGetInt_uint64_t(color_index_py, color_index);

    if (size > 0)
    {
	    interval_arg.start = addr;
	    interval_arg.last = addr + (size - 1);

	    taint_check_color(color_index, self->taint->nb_colors);
	    taint_memory_generic_access(self->taint, color_index, interval_arg, access_type);
    }

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_taint_memory(PyTaint* self, PyObject* args)
{
	return cpu_access_memory(self, args, ADD);
}

PyObject *
cpu_untaint_memory(PyTaint* self, PyObject* args)
{
	return cpu_access_memory(self, args, REMOVE);
}

PyObject *
cpu_untaint_all_memory(PyTaint* self)
{
	taint_remove_all_memory(self->taint);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_color_untaint_all_memory(PyTaint* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);
	taint_color_remove_all_memory(self->taint, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_untaint_all(PyTaint* self)
{
	taint_remove_all_registers(self->taint);
	taint_remove_all_memory(self->taint);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_color_untaint_all(PyTaint* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);
	taint_color_remove_all_registers(self->taint, color_index);
	taint_color_remove_all_memory(self->taint, color_index);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_init_taint(PyTaint* self, PyObject* args)
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

	self->taint = taint_init_colors(nb_colors, nb_regs, max_register_size);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject*
cpu_get_registers(struct rb_root ** registers,
		          uint64_t nb_registers,
		          uint32_t max_register_size)
{
	PyObject *tainted_registers = PyList_New(0);
    PyObject *tainted_interval_list, *tuple, *register_index_py, *start, *last;
	struct rb_root tainted_interval_tree;
    struct rb_node *rb_node;
	struct interval interval_arg;
    struct interval_tree_node *node;
	uint64_t register_index;

	interval_arg.start = DEFAULT_REG_START;
	interval_arg.last = DEFAULT_MAX_REG_SIZE-1;

	for(register_index = 0; register_index < nb_registers; register_index++)
	{
		tainted_interval_tree = taint_get_register(registers,
                                                   register_index,
                                                   interval_arg,
                                                   max_register_size);

		if (rb_first(&tainted_interval_tree) != NULL)
		{
            tainted_interval_list = PyList_New(0);
            register_index_py = PyLong_FromLong(register_index);

            rb_node = rb_first(&tainted_interval_tree);

            if (rb_node == NULL)
            {
                continue;
            }

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                start = PyLong_FromLong(node->interval.start);
                last = PyLong_FromLong(node->interval.last);

                tuple = PyTuple_New(2);
                PyTuple_SetItem(tuple, 0, start);
                PyTuple_SetItem(tuple, 1, last);
                PyList_Append(tainted_interval_list, tuple);

                rb_node = rb_next(rb_node);
            }
            tuple = PyTuple_New(2);
            PyTuple_SetItem(tuple, 0, register_index_py);
            PyTuple_SetItem(tuple, 1, tainted_interval_list);
            PyList_Append(tainted_registers, tuple);
		}
	}

	return tainted_registers;
}

PyObject *
cpu_get_last_register(PyTaint* self, PyObject* args, uint32_t event_type)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);

	struct rb_root ** registers;
	if (event_type == TAINT_EVENT)
		registers = self->taint->colors[color_index]
			.callback_info->last_tainted.registers;
	else
		registers = self->taint->colors[color_index]
			.callback_info->last_untainted.registers;

	return cpu_get_registers(registers,
				             self->taint->nb_registers,
				             self->taint->max_register_size);
}

PyObject*
cpu_get_last_tainted_registers(PyTaint* self, PyObject* args)
{
	return cpu_get_last_register(self, args, TAINT_EVENT);
}

PyObject *
cpu_get_last_untainted_registers(PyTaint* self, PyObject* args)
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
        start = PyLong_FromLong(node->interval.start);
        end = PyLong_FromLong(node->interval.last);

        tuple = PyTuple_New(2);
        PyTuple_SetItem(tuple, 0, start);
        PyTuple_SetItem(tuple, 1, end);
        PyList_Append(tainted_memory, tuple);

        rb_node = rb_next(rb_node);
    }

    return tainted_memory;
}

PyObject *
cpu_get_last_memory(PyTaint* self, PyObject* args, uint32_t event_type)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);

	struct rb_root * memory;
	if (event_type == TAINT_EVENT)
		memory = self->taint->colors[color_index].callback_info->last_tainted.memory;
	else
		memory = self->taint->colors[color_index].callback_info->last_untainted.memory;

	return cpu_get_memory(memory);
}

PyObject *
cpu_get_last_tainted_memory(PyTaint* self, PyObject* args)
{
	return cpu_get_last_memory(self, args, TAINT_EVENT);
}

PyObject *
cpu_get_last_untainted_memory(PyTaint* self, PyObject* args)
{
	return cpu_get_last_memory(self, args, UNTAINT_EVENT);
}

PyObject *
cpu_get_all_taint(PyTaint* self, PyObject* args)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);

	/* Registers */
	PyObject *tainted_registers
		= cpu_get_registers(self->taint->colors[color_index].registers,
				    self->taint->nb_registers,
				    self->taint->max_register_size);

	/* Memory */
	PyObject *tainted_memory = cpu_get_memory(self->taint->colors[color_index].memory);

	/* Joining data */
	PyObject *out_obj = PyTuple_New(2);

	PyTuple_SetItem(out_obj, 0, tainted_registers);
	PyTuple_SetItem(out_obj, 1, tainted_memory);

	return out_obj;
}

/* Set or unset exception flags */
PyObject *
cpu_enable_cb(PyTaint* self, PyObject* args, uint32_t cb)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);

	self->taint->colors[color_index].callback_info->exception_flag
		|= cb;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_enable_taint_reg_cb(PyTaint* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_TAINT_REG_CB);
}

PyObject *
cpu_enable_untaint_reg_cb(PyTaint* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_UNTAINT_REG_CB);
}

PyObject *
cpu_enable_taint_mem_cb(PyTaint* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_TAINT_MEM_CB);
}

PyObject *
cpu_enable_untaint_mem_cb(PyTaint* self, PyObject* args)
{
	return cpu_enable_cb(self, args, DO_UNTAINT_MEM_CB);
}

PyObject *
cpu_disable_cb(PyTaint* self, PyObject* args, uint32_t cb)
{
	PyObject *color_index_py;
	uint64_t color_index;

	if (!PyArg_ParseTuple(args, "O", &color_index_py))
		return NULL;

	PyGetInt_uint64_t(color_index_py, color_index);

	taint_check_color(color_index, self->taint->nb_colors);

	self->taint->colors[color_index].callback_info->exception_flag
		&= ~cb;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *
cpu_disable_taint_reg_cb(PyTaint* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_TAINT_REG_CB);
}

PyObject *
cpu_disable_untaint_reg_cb(PyTaint* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_UNTAINT_REG_CB);
}

PyObject *
cpu_disable_taint_mem_cb(PyTaint* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_TAINT_MEM_CB);
}

PyObject *
cpu_disable_untaint_mem_cb(PyTaint* self, PyObject* args)
{
	return cpu_disable_cb(self, args, DO_UNTAINT_MEM_CB);
}

void PyTaint_dealloc(PyTaint* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyObject * PyTaint_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyTaint *self;

    self = (PyTaint *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

static int
PyTaint_init(PyTaint *self, PyObject *args, PyObject *kwds)
{
    self->taint = taint_init_colors(0, 0, 0);
    return 0;
}

static PyMemberDef PyTaint_members[] = {
    // TODO add colors
    {NULL}  /* Sentinel */
};

static PyGetSetDef PyTaint_getseters[] = {
    // TODO add colors
    {NULL}  /* Sentinel */
};

static PyMethodDef PyTaint_methods[] = {
    {"taint_register", (PyCFunction)cpu_taint_register, METH_VARARGS, \
	 "X"}, \
	{"untaint_register", (PyCFunction)cpu_untaint_register, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_registers_of_color", (PyCFunction)cpu_color_untaint_all_registers, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_registers", (PyCFunction)cpu_untaint_all_registers, METH_NOARGS, \
	 "X"}, \
	{"taint_memory", (PyCFunction)cpu_taint_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_memory", (PyCFunction)cpu_untaint_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_memory_of_color", (PyCFunction)cpu_color_untaint_all_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_memory", (PyCFunction)cpu_untaint_all_memory, METH_NOARGS, \
	 "X"}, \
	{"untaint_all_of_color", (PyCFunction)cpu_color_untaint_all, METH_VARARGS, \
	 "X"}, \
	{"untaint_all", (PyCFunction)cpu_untaint_all, METH_NOARGS, \
	 "X"}, \
	{"init_taint_analysis", (PyCFunction)cpu_init_taint, METH_VARARGS, \
	 "X"}, \
	{"last_tainted_registers", (PyCFunction)cpu_get_last_tainted_registers, METH_VARARGS, \
	 "X"}, \
	{"last_untainted_registers", (PyCFunction)cpu_get_last_untainted_registers, METH_VARARGS, \
	 "X"}, \
	{"last_tainted_memory", (PyCFunction)cpu_get_last_tainted_memory, METH_VARARGS, \
	 "X"}, \
	{"last_untainted_memory", (PyCFunction)cpu_get_last_untainted_memory, METH_VARARGS, \
	 "X"}, \
	{"get_all_taint", (PyCFunction)cpu_get_all_taint, METH_VARARGS, \
	 "X"}, \
	{"enable_taint_reg_cb", (PyCFunction)cpu_enable_taint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_untaint_reg_cb", (PyCFunction)cpu_enable_untaint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_taint_mem_cb", (PyCFunction)cpu_enable_taint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_untaint_mem_cb", (PyCFunction)cpu_enable_untaint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_taint_reg_cb", (PyCFunction)cpu_disable_taint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_untaint_reg_cb", (PyCFunction)cpu_disable_untaint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_taint_mem_cb", (PyCFunction)cpu_disable_taint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_untaint_mem_cb", (PyCFunction)cpu_disable_untaint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{NULL}  /* Sentinel */
};

static PyTypeObject PyTaintType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    PYTHON_CLASS_NAME".Taint",  /*tp_name*/
    sizeof(PyTaint),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)PyTaint_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Taint objects",          /* tp_doc */
    0,			       /* tp_traverse */
    0,			       /* tp_clear */
    0,			       /* tp_richcompare */
    0,			       /* tp_weaklistoffset */
    0,			       /* tp_iter */
    0,			       /* tp_iternext */
    PyTaint_methods,            /* tp_methods */
    PyTaint_members,            /* tp_members */
    PyTaint_getseters,          /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)PyTaint_init,     /* tp_init */
    0,                         /* tp_alloc */
    PyTaint_new,                /* tp_new */
};

MOD_INIT(TaintMngr)
{
	PyObject *module = NULL;

	MOD_DEF(module, PYTHON_CLASS_NAME, PYTHON_CLASS_NAME" module", PyTaint_methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&PyTaintType) < 0)
		RET_MODULE;

	Py_INCREF(&PyTaintType);
	if (PyModule_AddObject(module, "Taint", (PyObject *)&PyTaintType) < 0)
		RET_MODULE;

	RET_MODULE;
}
