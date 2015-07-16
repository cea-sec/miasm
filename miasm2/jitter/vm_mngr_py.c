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
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include "queue.h"
#include "vm_mngr.h"
#include "vm_mngr_py.h"

#define MIN(a,b)  (((a)<(b))?(a):(b))
#define MAX(a,b)  (((a)>(b))?(a):(b))

extern struct memory_page_list_head memory_page_pool;
extern struct code_bloc_list_head code_bloc_pool;

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}



/* XXX POC signals */
VmMngr* global_vmmngr;

PyObject* _vm_get_exception(unsigned int xcpt)
{
	PyObject*p;

	if (!xcpt)
		p = NULL;
	else if (xcpt & EXCEPT_CODE_AUTOMOD)
		p = PyErr_Format( PyExc_RuntimeError, "EXCEPT_CODE_AUTOMOD" );
	else if (xcpt & EXCEPT_UNK_EIP)
		p = PyErr_Format( PyExc_RuntimeError, "EXCEPT_UNK_EIP" );
	else if (xcpt & EXCEPT_UNK_MEM_AD)
		p = PyErr_Format( PyExc_RuntimeError, "EXCEPT_UNK_MEM_AD" );

	else  p = PyErr_Format( PyExc_RuntimeError, "EXCEPT_UNKNOWN" );
	return p;
}


#define PyGetInt(item, value)						\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyInt_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		RAISE(PyExc_TypeError,"arg must be int");		\
	}								\


PyObject* vm_is_mem_mapped(VmMngr* self, PyObject* item)
{
	PyObject *addr;
	uint64_t page_addr;
	uint32_t ret;
	if (!PyArg_ParseTuple(item, "O", &addr))
		return NULL;

	PyGetInt(addr, page_addr);

	ret = is_mem_mapped(&self->vm_mngr, page_addr);
	return PyInt_FromLong((long)ret);
}



PyObject* vm_get_mem_base_addr(VmMngr* self, PyObject* item)
{
	PyObject *addr;

	uint64_t page_addr;
	uint64_t addr_base;
	unsigned int ret;

	if (!PyArg_ParseTuple(item, "O", &addr))
		return NULL;

	PyGetInt(addr, page_addr);

	ret = get_mem_base_addr(&self->vm_mngr, page_addr, &addr_base);
	if (ret == 0){
		Py_INCREF(Py_None);
		return Py_None;
	}
	return PyLong_FromUnsignedLongLong((uint64_t)addr_base);
}

static void sig_alarm(int signo)
{
	global_vmmngr->vm_mngr.exception_flags |= BREAK_SIGALARM;
	return;
}

PyObject* set_alarm(VmMngr* self)
{
	global_vmmngr = self;
	signal(SIGALRM, sig_alarm);
	return PyLong_FromUnsignedLongLong((uint64_t)0);
}



PyObject* vm_add_memory_page(VmMngr* self, PyObject* args)
{
	PyObject *addr;
	PyObject *access;
	PyObject *item_str;
	uint64_t buf_size;
	char* buf_data;
	Py_ssize_t length;
	uint64_t ret = 0x1337beef;
	uint64_t page_addr;
	uint64_t page_access;

	struct memory_page_node * mpn;

	if (!PyArg_ParseTuple(args, "OOO", &addr, &access, &item_str))
		return NULL;

	PyGetInt(addr, page_addr);
	PyGetInt(access, page_access);

	if(!PyString_Check(item_str))
		RAISE(PyExc_TypeError,"arg must be str");

	buf_size = PyString_Size(item_str);
	PyString_AsStringAndSize(item_str, &buf_data, &length);

	/*
	fprintf(stderr, "add page %"PRIX64" %"PRIX64" %"PRIX64"\n",
		page_addr, buf_size, page_access);
	*/
	mpn = create_memory_page_node(page_addr, buf_size, page_access);
	if (mpn == NULL)
		RAISE(PyExc_TypeError,"cannot create page");
	if (is_mpn_in_tab(&self->vm_mngr, mpn)) {
		free(mpn->ad_hp);
		free(mpn);
		RAISE(PyExc_TypeError,"known page in memory");
	}

	memcpy(mpn->ad_hp, buf_data, buf_size);
	add_memory_page(&self->vm_mngr, mpn);

	return PyLong_FromUnsignedLongLong((uint64_t)ret);

}



PyObject* vm_set_mem_access(VmMngr* self, PyObject* args)
{
	PyObject *addr;
	PyObject *access;

	uint64_t ret = 0x1337beef;
	uint64_t page_addr;
	uint64_t page_access;
	struct memory_page_node * mpn;

	if (!PyArg_ParseTuple(args, "OO", &addr, &access))
		return NULL;

	PyGetInt(addr, page_addr);
	PyGetInt(access, page_access);

	mpn = get_memory_page_from_address(&self->vm_mngr, page_addr);
	if (!mpn){
		PyErr_SetString(PyExc_RuntimeError, "cannot find address");
		return 0;
	}

	mpn->access = page_access;
	return PyLong_FromUnsignedLongLong((uint64_t)ret);
}

PyObject* vm_set_mem(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_buffer;
       Py_ssize_t py_length;

       char * buffer;
       uint64_t size;
       uint64_t addr;
       int ret = 0x1337;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_buffer))
	      return NULL;

       PyGetInt(py_addr, addr);

       if(!PyString_Check(py_buffer))
	      RAISE(PyExc_TypeError,"arg must be str");

       size = PyString_Size(py_buffer);
       PyString_AsStringAndSize(py_buffer, &buffer, &py_length);

       ret = vm_write_mem(&self->vm_mngr, addr, buffer, size);
       if (ret < 0)
	      RAISE(PyExc_TypeError,"arg must be str");

       check_write_code_bloc(&self->vm_mngr, size*8, addr);

       Py_INCREF(Py_None);
       return Py_None;
}




PyObject* vm_get_mem(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_len;

       uint64_t addr;
       uint64_t size;
       PyObject *obj_out;
       char * buf_out;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_len))
	      return NULL;

       PyGetInt(py_addr, addr);
       PyGetInt(py_len, size);

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, size);
       if (ret < 0) {
	      PyErr_SetString(PyExc_RuntimeError, "cannot find address");
	      return NULL;
       }

       obj_out = PyString_FromStringAndSize(buf_out, size);
       free(buf_out);
       return obj_out;
}


PyObject* vm_add_memory_breakpoint(VmMngr* self, PyObject* args)
{
	PyObject *ad;
	PyObject *size;
	PyObject *access;

	uint64_t b_ad;
	uint64_t b_size;
	uint64_t b_access;

	if (!PyArg_ParseTuple(args, "OOO", &ad, &size, &access))
		return NULL;

	PyGetInt(ad, b_ad);
	PyGetInt(size, b_size);
	PyGetInt(access, b_access);

	add_memory_breakpoint(&self->vm_mngr, b_ad, b_size, b_access);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_remove_memory_breakpoint(VmMngr* self, PyObject* args)
{
	PyObject *ad;
	PyObject *access;
	uint64_t b_ad;
	uint64_t b_access;

	if (!PyArg_ParseTuple(args, "OO", &ad, &access))
		return NULL;

	PyGetInt(ad, b_ad);
	PyGetInt(access, b_access);
	remove_memory_breakpoint(&self->vm_mngr, b_ad, b_access);

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_set_exception(VmMngr* self, PyObject* args)
{
	PyObject *item1;
	uint64_t i;

	if (!PyArg_ParseTuple(args, "O", &item1))
		return NULL;

	PyGetInt(item1, i);

	self->vm_mngr.exception_flags = i;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_get_exception(VmMngr* self, PyObject* args)
{
	return PyLong_FromUnsignedLongLong((uint64_t)self->vm_mngr.exception_flags);
}




PyObject* vm_init_memory_page_pool(VmMngr* self, PyObject* args)
{
    init_memory_page_pool(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* vm_init_code_bloc_pool(VmMngr* self, PyObject* args)
{
    init_code_bloc_pool(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject* vm_init_memory_breakpoint(VmMngr* self, PyObject* args)
{
    init_memory_breakpoint(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject* vm_reset_memory_breakpoint(VmMngr* self, PyObject* args)
{
    reset_memory_breakpoint(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject *vm_dump(PyObject* self)
{
	char* buf_final;
	PyObject* ret_obj;

	buf_final = dump(&((VmMngr* )self)->vm_mngr);
	ret_obj = PyString_FromString(buf_final);
	free(buf_final);
	return ret_obj;
}

PyObject* vm_dump_memory_breakpoint(VmMngr* self, PyObject* args)
{
	dump_memory_breakpoint_pool(&self->vm_mngr);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_get_all_memory(VmMngr* self, PyObject* args)
{
	PyObject *o;
	struct memory_page_node * mpn;
	PyObject *dict;
	PyObject *dict2;


	dict =  PyDict_New();

	LIST_FOREACH(mpn, &self->vm_mngr.memory_page_pool, next){

		dict2 =  PyDict_New();

		o = PyString_FromStringAndSize(mpn->ad_hp, mpn->size);
		PyDict_SetItemString(dict2, "data", o);
		Py_DECREF(o);

		o = PyInt_FromLong((long)mpn->size);
		PyDict_SetItemString(dict2, "size", o);
		Py_DECREF(o);

		o = PyInt_FromLong((long)mpn->access);
		PyDict_SetItemString(dict2, "access", o);
		Py_DECREF(o);

		o = PyInt_FromLong((long)mpn->ad);
		PyDict_SetItem(dict, o, dict2);
		Py_DECREF(o);
		Py_DECREF(dict2);
	}
	return dict;
}


PyObject* vm_reset_memory_page_pool(VmMngr* self, PyObject* args)
{
    reset_memory_page_pool(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject* vm_reset_code_bloc_pool(VmMngr* self, PyObject* args)
{
    reset_code_bloc_pool(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;

}


PyObject* vm_add_code_bloc(VmMngr *self, PyObject *args)
{
	PyObject *item1;
	PyObject *item2;
	uint64_t ret = 0x1337beef;
	uint64_t ad_start, ad_stop, ad_code = 0;

	struct code_bloc_node * cbp;

	if (!PyArg_ParseTuple(args, "OO", &item1, &item2))
		return NULL;

	PyGetInt(item1, ad_start);
	PyGetInt(item2, ad_stop);

	cbp = create_code_bloc_node(ad_start, ad_stop);
	cbp->ad_start = ad_start;
	cbp->ad_stop = ad_stop;
	cbp->ad_code = ad_code;
	add_code_bloc(&self->vm_mngr, cbp);
	return PyLong_FromUnsignedLongLong((uint64_t)ret);
}

PyObject* vm_dump_code_bloc_pool(VmMngr* self)
{
	dump_code_bloc_pool(&self->vm_mngr);
	Py_INCREF(Py_None);
	return Py_None;

}


PyObject* vm_set_addr2obj(VmMngr* self, PyObject* args)
{
	PyObject* addr2obj;

	if (!PyArg_ParseTuple(args, "O", &addr2obj))
		return NULL;

	if (self->vm_mngr.addr2obj != NULL){
		Py_DECREF(self->vm_mngr.addr2obj);
	}

	Py_INCREF(addr2obj);
	self->vm_mngr.addr2obj = addr2obj;
	Py_INCREF(Py_None);
	return Py_None;
}


static PyObject *
vm_set_big_endian(VmMngr *self, PyObject *value, void *closure)
{
	self->vm_mngr.sex   = __BIG_ENDIAN;
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
vm_set_little_endian(VmMngr *self, PyObject *value, void *closure)
{
	self->vm_mngr.sex   = __LITTLE_ENDIAN;
	Py_INCREF(Py_None);
	return Py_None;
}



/*
PyObject* add_jitbloc(VmMngr* self, PyObject* args)
{
	PyObject* jitobj;

	if (!PyArg_ParseTuple(args, "O", &addr2obj))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;

}
*/




static void
VmMngr_dealloc(VmMngr* self)
{
    vm_reset_memory_page_pool(self, NULL);
    vm_reset_code_bloc_pool(self, NULL);
    vm_reset_memory_breakpoint(self, NULL);
    self->ob_type->tp_free((PyObject*)self);
}


static PyObject *
VmMngr_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    VmMngr *self;

    self = (VmMngr *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

static PyObject *
VmMngr_get_vmmngr(VmMngr *self, void *closure)
{
	return PyLong_FromUnsignedLongLong((uint64_t)&(self->vm_mngr));
}

static int
VmMngr_set_vmmngr(VmMngr *self, PyObject *value, void *closure)
{
	PyErr_SetString(PyExc_TypeError, "immutable vmmngr");
	return -1;
}

static PyMemberDef VmMngr_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef VmMngr_methods[] = {
	{"init_memory_page_pool", (PyCFunction)vm_init_memory_page_pool, METH_VARARGS,
	 "X"},
	{"init_memory_breakpoint", (PyCFunction)vm_init_memory_breakpoint, METH_VARARGS,
	 "X"},
	{"init_code_bloc_pool",(PyCFunction)vm_init_code_bloc_pool, METH_VARARGS,
	 "X"},
	{"set_mem_access", (PyCFunction)vm_set_mem_access, METH_VARARGS,
	 "X"},
	{"set_mem", (PyCFunction)vm_set_mem, METH_VARARGS,
	 "X"},
	{"set_addr2obj", (PyCFunction)vm_set_addr2obj, METH_VARARGS,
	 "X"},
	{"add_code_bloc",(PyCFunction)vm_add_code_bloc, METH_VARARGS,
	 "X"},
	{"get_mem", (PyCFunction)vm_get_mem, METH_VARARGS,
	 "X"},
	{"add_memory_page",(PyCFunction)vm_add_memory_page, METH_VARARGS,
	 "X"},
	{"add_memory_breakpoint",(PyCFunction)vm_add_memory_breakpoint, METH_VARARGS,
	 "X"},
	{"remove_memory_breakpoint",(PyCFunction)vm_remove_memory_breakpoint, METH_VARARGS,
	 "X"},
	{"set_exception", (PyCFunction)vm_set_exception, METH_VARARGS,
	 "X"},
	{"dump_memory_breakpoint", (PyCFunction)vm_dump_memory_breakpoint, METH_VARARGS,
	 "X"},
	{"get_all_memory",(PyCFunction)vm_get_all_memory, METH_VARARGS,
	 "X"},
	{"reset_memory_page_pool", (PyCFunction)vm_reset_memory_page_pool, METH_VARARGS,
	 "X"},
	{"reset_memory_breakpoint", (PyCFunction)vm_reset_memory_breakpoint, METH_VARARGS,
	 "X"},
	{"reset_code_bloc_pool", (PyCFunction)vm_reset_code_bloc_pool, METH_VARARGS,
	 "X"},
	{"set_alarm", (PyCFunction)set_alarm, METH_VARARGS,
	 "X"},
	{"get_exception",(PyCFunction)vm_get_exception, METH_VARARGS,
	 "X"},
	{"get_exception",(PyCFunction)vm_get_exception, METH_VARARGS,
	 "X"},

	{"set_big_endian",(PyCFunction)vm_set_big_endian, METH_VARARGS,
	 "X"},
	{"set_little_endian",(PyCFunction)vm_set_little_endian, METH_VARARGS,
	 "X"},

	{NULL}  /* Sentinel */
};

static int
VmMngr_init(VmMngr *self, PyObject *args, PyObject *kwds)
{
	memset(&(self->vm_mngr), 0, sizeof(self->vm_mngr));
	return 0;
}

static PyGetSetDef VmMngr_getseters[] = {
    {"vmmngr",
     (getter)VmMngr_get_vmmngr, (setter)VmMngr_set_vmmngr,
     "first name",
     NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject VmMngrType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "VmMngr",                  /*tp_name*/
    sizeof(VmMngr),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)VmMngr_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    vm_dump,                   /*tp_repr*/
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
    "VmMngr objects",          /* tp_doc */
    0,			       /* tp_traverse */
    0,			       /* tp_clear */
    0,			       /* tp_richcompare */
    0,			       /* tp_weaklistoffset */
    0,			       /* tp_iter */
    0,			       /* tp_iternext */
    VmMngr_methods,            /* tp_methods */
    VmMngr_members,            /* tp_members */
    VmMngr_getseters,          /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)VmMngr_init,     /* tp_init */
    0,                         /* tp_alloc */
    VmMngr_new,                /* tp_new */
};


static PyMethodDef VmMngr_Methods[] = {
	{NULL, NULL, 0, NULL}        /* Sentinel */

};

static PyObject *Vm_Mngr_Error;

PyMODINIT_FUNC
initVmMngr(void)
{
    PyObject *m;

    if (PyType_Ready(&VmMngrType) < 0)
	return;

    m = Py_InitModule("VmMngr", VmMngr_Methods);
    if (m == NULL)
	    return;

    Vm_Mngr_Error = PyErr_NewException("VmMngr.error", NULL, NULL);
    Py_INCREF(Vm_Mngr_Error);
    PyModule_AddObject(m, "error", Vm_Mngr_Error);

    Py_INCREF(&VmMngrType);
    PyModule_AddObject(m, "Vm", (PyObject *)&VmMngrType);
}
