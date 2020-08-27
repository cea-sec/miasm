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
#include "compat_py23.h"
#include "queue.h"
#include "vm_mngr.h"
#include "bn.h"
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

static void sig_alarm(int signo)
{
	global_vmmngr->vm_mngr.exception_flags |= BREAK_SIGALARM;
	return;
}

PyObject* set_alarm(VmMngr* self)
{
	global_vmmngr = self;
	signal(SIGALRM, sig_alarm);

	Py_INCREF(Py_None);
	return Py_None;
}



PyObject* vm_add_memory_page(VmMngr* self, PyObject* args)
{
	PyObject *addr;
	PyObject *access;
	PyObject *item_str;
	PyObject *name=NULL;
	uint64_t buf_size;
	size_t buf_size_st;
	char* buf_data;
	Py_ssize_t length;
	uint64_t page_addr;
	uint64_t page_access;
	const char *name_ptr;

	struct memory_page_node * mpn;

	if (!PyArg_ParseTuple(args, "OOO|O", &addr, &access, &item_str, &name))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(addr, page_addr);
	PyGetInt_uint64_t(access, page_access);

	if(!PyBytes_Check(item_str))
		RAISE(PyExc_TypeError,"arg must be bytes");

	buf_size = PyBytes_Size(item_str);
	PyBytes_AsStringAndSize(item_str, &buf_data, &length);

	if (name == NULL) {
		name_ptr = (char*)"";
	} else {
		PyGetStr(name_ptr, name);
	}
	mpn = create_memory_page_node(page_addr, (size_t)buf_size, (unsigned int)page_access, name_ptr);
	if (mpn == NULL)
		RAISE(PyExc_TypeError,"cannot create page");
	if (is_mpn_in_tab(&self->vm_mngr, mpn)) {
		free(mpn->ad_hp);
		free(mpn);
		RAISE(PyExc_TypeError,"known page in memory");
	}

	if (buf_size > SIZE_MAX) {
		      fprintf(stderr, "Size too big\n");
		      exit(EXIT_FAILURE);
	}
	buf_size_st = (size_t) buf_size;

	memcpy(mpn->ad_hp, buf_data, buf_size_st);
	add_memory_page(&self->vm_mngr, mpn);

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_remove_memory_page(VmMngr* self, PyObject* args)
{
  PyObject *addr;
  uint64_t page_addr;

  if (!PyArg_ParseTuple(args, "O", &addr))
    RAISE(PyExc_TypeError,"Cannot parse arguments");

  PyGetInt_uint64_t(addr, page_addr);

  remove_memory_page(&self->vm_mngr, page_addr);

  Py_INCREF(Py_None);
  return Py_None;


}

PyObject* vm_set_mem_access(VmMngr* self, PyObject* args)
{
	PyObject *addr;
	PyObject *access;
	uint64_t page_addr;
	uint64_t page_access;
	struct memory_page_node * mpn;

	if (!PyArg_ParseTuple(args, "OO", &addr, &access))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(addr, page_addr);
	PyGetInt_uint64_t(access, page_access);

	mpn = get_memory_page_from_address(&self->vm_mngr, page_addr, 1);
	if (!mpn){
		PyErr_SetString(PyExc_RuntimeError, "cannot find address");
		return 0;
	}

	mpn->access = page_access;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_set_mem(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_buffer;
       Py_ssize_t py_length;

       char * buffer;
       Py_ssize_t pysize;
       uint64_t addr;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_buffer))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);

       if (!PyBytes_Check(py_buffer))
	       RAISE(PyExc_TypeError,"arg must be bytes");

       pysize = PyBytes_Size(py_buffer);
       if (pysize < 0) {
	       RAISE(PyExc_TypeError,"Python error");
       }
       PyBytes_AsStringAndSize(py_buffer, &buffer, &py_length);

       ret = vm_write_mem(&self->vm_mngr, addr, buffer, pysize);
       if (ret < 0)
	      RAISE(PyExc_TypeError, "Error in set_mem");

       add_mem_write(&self->vm_mngr, addr, (size_t)pysize);
       check_invalid_code_blocs(&self->vm_mngr);

       Py_INCREF(Py_None);
       return Py_None;
}



PyObject* vm_get_mem_access(VmMngr* self, PyObject* args)
{
	PyObject *py_addr;
	uint64_t page_addr;
	struct memory_page_node * mpn;

	if (!PyArg_ParseTuple(args, "O", &py_addr))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(py_addr, page_addr);

	mpn = get_memory_page_from_address(&self->vm_mngr, page_addr, 1);
	if (!mpn){
		PyErr_SetString(PyExc_RuntimeError, "cannot find address");
		return 0;
	}

	return PyLong_FromUnsignedLongLong((uint64_t)mpn->access);
}

PyObject* vm_get_mem(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_len;

       uint64_t addr;
       uint64_t size;
       size_t size_st;
       PyObject *obj_out;
       char * buf_out;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_len))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);
       PyGetInt_uint64_t(py_len, size);

       if (size > SIZE_MAX) {
	       fprintf(stderr, "Size too big\n");
	       exit(EXIT_FAILURE);
       }
       size_st = (size_t) size;

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, size_st);
       if (ret < 0) {
	       RAISE(PyExc_RuntimeError,"Cannot find address");
       }

       obj_out = PyBytes_FromStringAndSize(buf_out, size_st);
       free(buf_out);
       return obj_out;
}

PyObject* vm_get_u8(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;

       uint64_t addr;
       PyObject *obj_out;
       char * buf_out;
       int ret;
       uint32_t value;

       if (!PyArg_ParseTuple(args, "O", &py_addr))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, 1);
       if (ret < 0) {
	       RAISE(PyExc_RuntimeError,"Cannot find address");
       }

       value = *(uint8_t*)buf_out;

       obj_out = PyLong_FromUnsignedLongLong(value);
       free(buf_out);
       return obj_out;
}

PyObject* vm_get_u16(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;

       uint64_t addr;
       PyObject *obj_out;
       char * buf_out;
       int ret;
       uint16_t value;

       if (!PyArg_ParseTuple(args, "O", &py_addr))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, 2);
       if (ret < 0) {
	       RAISE(PyExc_RuntimeError,"Cannot find address");
       }

       value = set_endian16(&self->vm_mngr, *(uint16_t*)buf_out);

       obj_out = PyLong_FromUnsignedLongLong(value);
       free(buf_out);
       return obj_out;
}

PyObject* vm_get_u32(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;

       uint64_t addr;
       PyObject *obj_out;
       char * buf_out;
       int ret;
       uint32_t value;

       if (!PyArg_ParseTuple(args, "O", &py_addr))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, 4);
       if (ret < 0) {
	       RAISE(PyExc_RuntimeError,"Cannot find address");
       }

       value = set_endian32(&self->vm_mngr, *(uint32_t*)buf_out);

       obj_out = PyLong_FromUnsignedLongLong(value);
       free(buf_out);
       return obj_out;
}


PyObject* vm_get_u64(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;

       uint64_t addr;
       PyObject *obj_out;
       char * buf_out;
       int ret;
       uint64_t value;

       if (!PyArg_ParseTuple(args, "O", &py_addr))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);

       ret = vm_read_mem(&self->vm_mngr, addr, &buf_out, 8);
       if (ret < 0) {
	       RAISE(PyExc_RuntimeError,"Cannot find address");
       }

       value = set_endian64(&self->vm_mngr, *(uint64_t*)buf_out);

       obj_out = PyLong_FromUnsignedLongLong(value);
       free(buf_out);
       return obj_out;
}


PyObject* vm_set_u8(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_val;
       uint8_t value;
       uint64_t addr;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_val))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);
       PyGetInt_uint8_t(py_val, value);

       ret = vm_write_mem(&self->vm_mngr, addr, (char*)&value, 1);
       if (ret < 0)
	      RAISE(PyExc_TypeError, "Error in set_mem");

       add_mem_write(&self->vm_mngr, addr, 1);
       check_invalid_code_blocs(&self->vm_mngr);

       Py_INCREF(Py_None);
       return Py_None;
}

PyObject* vm_set_u16(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_val;
       uint16_t value;

       uint64_t addr;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_val))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);
       PyGetInt_uint16_t(py_val, value);

       value = set_endian16(&self->vm_mngr, value);
       ret = vm_write_mem(&self->vm_mngr, addr, (char*)&value, 2);
       if (ret < 0)
	      RAISE(PyExc_TypeError, "Error in set_mem");

       add_mem_write(&self->vm_mngr, addr, 2);
       check_invalid_code_blocs(&self->vm_mngr);

       Py_INCREF(Py_None);
       return Py_None;
}

PyObject* vm_set_u32(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_val;
       uint32_t value;
       uint64_t addr;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_val))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);
       PyGetInt_uint32_t(py_val, value);

       value = set_endian32(&self->vm_mngr, value);

       ret = vm_write_mem(&self->vm_mngr, addr, (char*)&value, 4);
       if (ret < 0)
	      RAISE(PyExc_TypeError, "Error in set_mem");

       add_mem_write(&self->vm_mngr, addr, 4);
       check_invalid_code_blocs(&self->vm_mngr);

       Py_INCREF(Py_None);
       return Py_None;
}

PyObject* vm_set_u64(VmMngr* self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_val;
       uint64_t value;
       uint64_t addr;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_val))
	       RAISE(PyExc_TypeError,"Cannot parse arguments");

       PyGetInt_uint64_t(py_addr, addr);
       PyGetInt_uint64_t(py_val, value);

       value = set_endian64(&self->vm_mngr, value);

       ret = vm_write_mem(&self->vm_mngr, addr, (char*)&value, 8);
       if (ret < 0)
	      RAISE(PyExc_TypeError, "Error in set_mem");

       add_mem_write(&self->vm_mngr, addr, 8);
       check_invalid_code_blocs(&self->vm_mngr);

       Py_INCREF(Py_None);
       return Py_None;
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
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(ad, b_ad);
	PyGetInt_uint64_t(size, b_size);
	PyGetInt_uint64_t(access, b_access);

	add_memory_breakpoint(&self->vm_mngr, b_ad, b_size, (unsigned int)b_access);

	/* Raise exception in the following pattern:
	   - set_mem(XXX)
	   - add_memory_breakpoint(XXX)
	   -> Here, there is a pending breakpoint not raise
	 */
	check_memory_breakpoint(&self->vm_mngr);

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
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(ad, b_ad);
	PyGetInt_uint64_t(access, b_access);
	remove_memory_breakpoint(&self->vm_mngr, b_ad, (unsigned int)b_access);

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_set_exception(VmMngr* self, PyObject* args)
{
	PyObject *item1;
	uint64_t exception_flags;

	if (!PyArg_ParseTuple(args, "O", &item1))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(item1, exception_flags);

	self->vm_mngr.exception_flags = exception_flags;
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

PyObject* vm_reset_memory_access(VmMngr* self, PyObject* args)
{
    reset_memory_access(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* py_add_mem_read(VmMngr* self, PyObject* args)
{
	PyObject *py_addr;
	PyObject *py_size;
	uint64_t addr;
	uint64_t size;

	if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_size))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(py_addr, addr);
	PyGetInt_uint64_t(py_size, size);
	add_mem_read(&self->vm_mngr, addr, size);
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject* py_add_mem_write(VmMngr* self, PyObject* args)
{
	PyObject *py_addr;
	PyObject *py_size;
	uint64_t addr;
	uint64_t size;

	if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_size))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(py_addr, addr);
	PyGetInt_uint64_t(py_size, size);
	add_mem_write(&self->vm_mngr, addr, size);
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject* vm_check_invalid_code_blocs(VmMngr* self, PyObject* args)
{
    check_invalid_code_blocs(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* vm_check_memory_breakpoint(VmMngr* self, PyObject* args)
{
    check_memory_breakpoint(&self->vm_mngr);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *vm_dump(PyObject* self)
{
	char* buf_final;
	PyObject* ret_obj;

	buf_final = dump(&((VmMngr* )self)->vm_mngr);
	ret_obj = PyUnicode_FromString(buf_final);
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
	int i;


	dict =  PyDict_New();

	for (i=0;i<self->vm_mngr.memory_pages_number; i++) {
		mpn = &self->vm_mngr.memory_pages_array[i];

		dict2 =  PyDict_New();

		o = PyBytes_FromStringAndSize(mpn->ad_hp, mpn->size);
		PyDict_SetItemString(dict2, "data", o);
		Py_DECREF(o);

		o = PyLong_FromLong((long)mpn->size);
		PyDict_SetItemString(dict2, "size", o);
		Py_DECREF(o);

		o = PyLong_FromLong((long)mpn->access);
		PyDict_SetItemString(dict2, "access", o);
		Py_DECREF(o);

		o = PyLong_FromUnsignedLongLong(mpn->ad);
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
	uint64_t ad_start, ad_stop, ad_code = 0;

	struct code_bloc_node * cbp;

	if (!PyArg_ParseTuple(args, "OO", &item1, &item2))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(item1, ad_start);
	PyGetInt_uint64_t(item2, ad_stop);

	cbp = create_code_bloc_node(ad_start, ad_stop);
	cbp->ad_start = ad_start;
	cbp->ad_stop = ad_stop;
	cbp->ad_code = ad_code;
	add_code_bloc(&self->vm_mngr, cbp);

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_dump_code_bloc_pool(VmMngr* self)
{
	dump_code_bloc_pool(&self->vm_mngr);
	Py_INCREF(Py_None);
	return Py_None;

}



PyObject* vm_is_mapped(VmMngr* self, PyObject* args)
{
	PyObject *ad;
	PyObject *size;
	uint64_t b_ad;
	size_t b_size;
	int ret;

	if (!PyArg_ParseTuple(args, "OO", &ad, &size))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint64_t(ad, b_ad);
	PyGetInt_size_t(size, b_size);
	ret = is_mapped(&self->vm_mngr, b_ad, b_size);
	return PyLong_FromUnsignedLongLong((uint64_t)ret);
}

PyObject* vm_get_memory_read(VmMngr* self, PyObject* args)
{
	PyObject* result;
	result = get_memory_read(&self->vm_mngr);
	Py_INCREF(result);
	return result;
}

PyObject* vm_get_memory_write(VmMngr* self, PyObject* args)
{
	PyObject* result;
	result = get_memory_write(&self->vm_mngr);
	Py_INCREF(result);
	return result;
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


static PyObject *
vm_is_little_endian(VmMngr *self, PyObject *value, void *closure)
{
	if (self->vm_mngr.sex == __BIG_ENDIAN) {
		return PyLong_FromUnsignedLongLong(0);
	} else {
		return PyLong_FromUnsignedLongLong(1);
	}
}


static void
VmMngr_dealloc(VmMngr* self)
{
    vm_reset_memory_page_pool(self, NULL);
    vm_reset_code_bloc_pool(self, NULL);
    vm_reset_memory_breakpoint(self, NULL);
    Py_TYPE(self)->tp_free((PyObject*)self);
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
	return PyLong_FromUnsignedLongLong((uint64_t)(intptr_t)&(self->vm_mngr));
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
	 "init_memory_page_pool() -> Initialize the VmMngr memory"},
	{"init_memory_breakpoint", (PyCFunction)vm_init_memory_breakpoint, METH_VARARGS,
	 "init_memory_breakpoint() -> Initialize the VmMngr memory breakpoints"},
	{"init_code_bloc_pool",(PyCFunction)vm_init_code_bloc_pool, METH_VARARGS,
	 "init_code_bloc_pool() -> Initialize the VmMngr jitted code blocks"},
	{"set_mem_access", (PyCFunction)vm_set_mem_access, METH_VARARGS,
	 "set_mem_access(address, access) -> Change the protection of the page at @address with @access"},
	{"set_mem", (PyCFunction)vm_set_mem, METH_VARARGS,
	 "set_mem(address, data) -> Set a @data in memory at @address"},
	{"is_mapped", (PyCFunction)vm_is_mapped, METH_VARARGS,
	 "is_mapped(address, size) -> Check if the memory region at @address of @size bytes is fully mapped"},
	{"add_code_bloc",(PyCFunction)vm_add_code_bloc, METH_VARARGS,
	 "add_code_bloc(address_start, address_stop) -> Add a jitted code block between [@address_start, @address_stop["},
	{"get_mem_access", (PyCFunction)vm_get_mem_access, METH_VARARGS,
	 "get_mem_access(address) -> Retrieve the memory protection of the page at @address"},
	{"get_mem", (PyCFunction)vm_get_mem, METH_VARARGS,
	 "get_mem(addr, size) -> Get the memory content at @address of @size bytes"},

	{"get_u8", (PyCFunction)vm_get_u8, METH_VARARGS,
	 "get_u8(addr) -> Get a u8 at @address of @size bytes (vm endianness)"},
	{"get_u16", (PyCFunction)vm_get_u16, METH_VARARGS,
	 "get_u16(addr) -> Get a u16 at @address of @size bytes (vm endianness)"},
	{"get_u32", (PyCFunction)vm_get_u32, METH_VARARGS,
	 "get_u32(addr) -> Get a u32 at @address of @size bytes (vm endianness)"},
	{"get_u64", (PyCFunction)vm_get_u64, METH_VARARGS,
	 "get_u64(addr) -> Get a u64 at @address of @size bytes (vm endianness)"},


	{"set_u8", (PyCFunction)vm_set_u8, METH_VARARGS,
	 "set_u8(addr, value) -> Set a u8 at @address of @size bytes (vm endianness)"},
	{"set_u16", (PyCFunction)vm_set_u16, METH_VARARGS,
	 "set_u16(addr, value) -> Set a u16 at @address of @size bytes (vm endianness)"},
	{"set_u32", (PyCFunction)vm_set_u32, METH_VARARGS,
	 "set_u32(addr, value) -> Set a u32 at @address of @size bytes (vm endianness)"},
	{"set_u64", (PyCFunction)vm_set_u64, METH_VARARGS,
	 "set_u64(addr, value) -> Set a u64 at @address of @size bytes (vm endianness)"},

	{"add_memory_page",(PyCFunction)vm_add_memory_page, METH_VARARGS,
	 "add_memory_page(address, access, content [, cmt]) -> Maps a memory page at @address of len(@content) bytes containing @content with protection @access\n"
	"@cmt is a comment linked to the memory page"},
	{"remove_memory_page",(PyCFunction)vm_remove_memory_page, METH_VARARGS,
	 "remove_memory_page(address) -> removes a previously allocated memory page at @address"},
	{"add_memory_breakpoint",(PyCFunction)vm_add_memory_breakpoint, METH_VARARGS,
	 "add_memory_breakpoint(address, size, access) -> Add a memory breakpoint at @address of @size bytes with @access type"},
	{"remove_memory_breakpoint",(PyCFunction)vm_remove_memory_breakpoint, METH_VARARGS,
	 "remove_memory_breakpoint(address, access) -> Remove a memory breakpoint at @address with @access type"},
	{"set_exception", (PyCFunction)vm_set_exception, METH_VARARGS,
	 "set_exception(exception) -> Set the VmMngr exception flags to @exception"},
	{"dump_memory_breakpoint", (PyCFunction)vm_dump_memory_breakpoint, METH_VARARGS,
	 "dump_memory_breakpoint() -> Lists each memory breakpoint"},
	{"get_all_memory",(PyCFunction)vm_get_all_memory, METH_VARARGS,
	 "get_all_memory() -> Returns a dictionary representing the VmMngr memory.\n"
	 "Keys are the addresses of each memory page.\n"
	 "Values are another dictionary containing page properties ('data', 'size', 'access')"
	},
	{"reset_memory_page_pool", (PyCFunction)vm_reset_memory_page_pool, METH_VARARGS,
	 "reset_memory_page_pool() -> Remove all memory pages"},
	{"reset_memory_breakpoint", (PyCFunction)vm_reset_memory_breakpoint, METH_VARARGS,
	 "reset_memory_breakpoint() -> Remove all memory breakpoints"},
	{"reset_code_bloc_pool", (PyCFunction)vm_reset_code_bloc_pool, METH_VARARGS,
	 "reset_code_bloc_pool() -> Remove all jitted blocks"},
	{"set_alarm", (PyCFunction)set_alarm, METH_VARARGS,
	 "set_alarm() -> Force a timer based alarm during a code emulation"},
	{"get_exception",(PyCFunction)vm_get_exception, METH_VARARGS,
	 "get_exception() -> Returns the VmMngr exception flags"},
	{"set_big_endian",(PyCFunction)vm_set_big_endian, METH_VARARGS,
	 "set_big_endian() -> Set the VmMngr to Big Endian"},
	{"set_little_endian",(PyCFunction)vm_set_little_endian, METH_VARARGS,
	 "set_little_endian() -> Set the VmMngr to Little Endian"},
	{"is_little_endian",(PyCFunction)vm_is_little_endian, METH_VARARGS,
	 "is_little_endian() -> Return True if the VmMngr is Little Endian"},
	{"get_memory_read",(PyCFunction)vm_get_memory_read, METH_VARARGS,
	 "get_memory_read() -> Retrieve last instruction READ access\n"
	 "This function is only valid in a memory breakpoint callback."
	},
	{"get_memory_write",(PyCFunction)vm_get_memory_write, METH_VARARGS,
	 "get_memory_write() -> Retrieve last instruction WRITE access\n"
	 "This function is only valid in a memory breakpoint callback."
	},
	{"reset_memory_access",(PyCFunction)vm_reset_memory_access, METH_VARARGS,
	 "reset_memory_access() -> Reset last memory READ/WRITE"},
	{"add_mem_read",(PyCFunction)py_add_mem_read, METH_VARARGS,
	 "add_mem_read(address, size) -> Add a READ access at @address of @size bytes"},
	{"add_mem_write",(PyCFunction)py_add_mem_write, METH_VARARGS,
	 "add_mem_write(address, size) -> Add a WRITE access at @address of @size bytes"},
	{"check_invalid_code_blocs",(PyCFunction)vm_check_invalid_code_blocs, METH_VARARGS,
	 "check_invalid_code_blocs() -> Set the AUTOMOD flag in exception in case of automodified code"},
	{"check_memory_breakpoint",(PyCFunction)vm_check_memory_breakpoint, METH_VARARGS,
	 "check_memory_breakpoint() -> Set the BREAKPOINT_MEMORY flag in exception in case of memory breakpoint occurred"},

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
     "vmmngr object",
     NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject VmMngrType = {
    PyVarObject_HEAD_INIT(NULL, 0)
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
    "VmMngr object",           /* tp_doc */
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

char vm_mngr_mod_docs[] = "vm_mngr module.";
char vm_mngr_mod_name[] = "VmMngr";


MOD_INIT(VmMngr)
{
	PyObject *module = NULL;

	MOD_DEF(module, "VmMngr", "vm_mngr module", VmMngr_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&VmMngrType) < 0)
		RET_MODULE;

	Py_INCREF(&VmMngrType);
	if (PyModule_AddObject(module, "Vm", (PyObject *)&VmMngrType) < 0)
		RET_MODULE;

	RET_MODULE;
}

bn_t PyLong_to_bn(PyObject* py_long)
{
	int j;
	uint64_t tmp_mask;
	PyObject* py_tmp;
	PyObject* py_long_tmp;
	PyObject* cst_32;
	PyObject* cst_ffffffff;
	bn_t bn;

	cst_ffffffff = PyLong_FromLong(0xffffffff);
	cst_32 = PyLong_FromLong(32);
	bn = bignum_from_int(0);

	for (j = 0; j < BN_BYTE_SIZE; j += 4) {
		py_tmp = PyObject_CallMethod(py_long, "__and__", "O", cst_ffffffff);
		py_long_tmp = PyObject_CallMethod(py_long, "__rshift__", "O", cst_32);
		Py_DECREF(py_long);
		py_long = py_long_tmp;
		tmp_mask = PyLong_AsUnsignedLongLongMask(py_tmp);
		Py_DECREF(py_tmp);
		bn = bignum_or(bn, bignum_lshift(bignum_from_uint64(tmp_mask), 8 * j));
	}

	Py_DECREF(cst_32);
	Py_DECREF(cst_ffffffff);

	return bn;
}

PyObject* bn_to_PyLong(bn_t bn)
{
	int j;
	PyObject* py_long;
	PyObject* py_long_new;
	PyObject* py_tmp;
	PyObject* cst_32;
	uint64_t tmp;

	py_long = PyLong_FromLong(0);
	cst_32 = PyLong_FromLong(32);

	for (j = BN_BYTE_SIZE - 4; j >= 0 ; j -= 4) {
		tmp = bignum_to_uint64(bignum_mask(bignum_rshift(bn, 8 * j), 32));
		py_tmp = PyLong_FromUnsignedLong((unsigned long)tmp);
		py_long_new = PyObject_CallMethod(py_long, "__lshift__", "O", cst_32);
		Py_DECREF(py_long);
		py_long = PyObject_CallMethod(py_long_new, "__add__", "O", py_tmp);
		Py_DECREF(py_long_new);
		Py_DECREF(py_tmp);
	}

	Py_DECREF(cst_32);

	return py_long;
}
