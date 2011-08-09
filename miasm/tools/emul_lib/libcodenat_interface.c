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
#include "queue.h"
#include "libcodenat.h"

#define MIN(a,b)  (((a)<(b))?(a):(b))
#define MAX(a,b)  (((a)>(b))?(a):(b))

extern struct memory_page_list_head memory_page_pool;
extern struct code_bloc_list_head code_bloc_pool;

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}

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

PyObject* _vm_get_all_memory(void)
{
    struct memory_page_node * mpn;
    PyObject *dict;
    PyObject *dict2;

    PyObject *o;

    dict =  PyDict_New();

    LIST_FOREACH(mpn, &memory_page_pool, next){

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


PyObject* _vm_get_gpreg(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    o = PyInt_FromLong((long)vmcpu.eax);
    PyDict_SetItemString(dict, "eax", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.ebx);
    PyDict_SetItemString(dict, "ebx", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.ecx);
    PyDict_SetItemString(dict, "ecx", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.edx);
    PyDict_SetItemString(dict, "edx", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.esi);
    PyDict_SetItemString(dict, "esi", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.edi);
    PyDict_SetItemString(dict, "edi", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.esp);
    PyDict_SetItemString(dict, "esp", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.ebp);
    PyDict_SetItemString(dict, "ebp", o);
    Py_DECREF(o);
    o = PyInt_FromLong((long)vmcpu.eip);
    PyDict_SetItemString(dict, "eip", o);
    Py_DECREF(o);

    return dict;
}

reg_dict gpreg_dict[] = { {.name = "eax", .ptr = &(vmcpu.eax)},
			  {.name = "ebx", .ptr = &(vmcpu.ebx)},
			  {.name = "ecx", .ptr = &(vmcpu.ecx)},
			  {.name = "edx", .ptr = &(vmcpu.edx)},
			  {.name = "esi", .ptr = &(vmcpu.esi)},
			  {.name = "edi", .ptr = &(vmcpu.edi)},
			  {.name = "esp", .ptr = &(vmcpu.esp)},
			  {.name = "ebp", .ptr = &(vmcpu.ebp)},
			  {.name = "eip", .ptr = &(vmcpu.eip)},
};

PyObject* _vm_set_gpreg(PyObject *dict)
{
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    unsigned int val;
    unsigned int i, found;

    if(!PyDict_Check(dict))
	    RAISE(PyExc_TypeError, "arg must be dict");
    while(PyDict_Next(dict, &pos, &d_key, &d_value)){
	    if(!PyString_Check(d_key))
		    RAISE(PyExc_TypeError, "key must be str");

	    if (PyInt_Check(d_value)){
		    val = (unsigned int)PyInt_AsLong(d_value);
	    }
	    else if (PyLong_Check(d_value)){
		    val = (unsigned int)PyInt_AsUnsignedLongLongMask(d_value);
	    }
	    else{
		    RAISE(PyExc_TypeError,"value must be int");
	    }

	    found = 0;
	    for (i=0; i < sizeof(gpreg_dict)/sizeof(reg_dict); i++){
		    if (strcmp(PyString_AsString(d_key), gpreg_dict[i].name))
			    continue;
		    *(gpreg_dict[i].ptr) = val;
		    found = 1;
		    break;
	    }

	    if (found)
		    continue;
	    printf("unkown key: %s\n", PyString_AsString(d_key));
	    RAISE(PyExc_ValueError, "unkown reg");
    }
    return NULL;
}


PyObject* _vm_add_memory_page(PyObject *item, PyObject *access, PyObject *item_str)
{
    unsigned int buf_size;
    char* buf_data;
    Py_ssize_t length;
    int ret = 0x1337beef;
    unsigned int page_addr;
    unsigned int page_access;

    struct memory_page_node * mpn;

    if (PyInt_Check(item)){
	    page_addr = (unsigned int)PyInt_AsLong(item);
    }
    else if (PyLong_Check(item)){
	    page_addr = (unsigned int)PyInt_AsUnsignedLongLongMask(item);
    }
    else{
	    RAISE(PyExc_TypeError,"arg1 must be int");
    }



    if (PyInt_Check(access)){
	    page_access = (unsigned int)PyInt_AsLong(access);
    }
    else if (PyLong_Check(item)){
	    page_access = (unsigned int)PyInt_AsUnsignedLongLongMask(access);
    }
    else{
	    RAISE(PyExc_TypeError,"arg2 must be int");
    }



    if(!PyString_Check(item_str))
       RAISE(PyExc_TypeError,"arg must be str");

    buf_size = PyString_Size(item_str);
    PyString_AsStringAndSize(item_str, &buf_data, &length);


    mpn = create_memory_page_node(page_addr, buf_size, page_access);
    memcpy(mpn->ad_hp, buf_data, buf_size);
    add_memory_page(mpn);

    return PyInt_FromLong((long)ret);
}

PyObject* _call_pyfunc_from_globals(char* funcname)
{
    PyObject  *mod,  *func, *rslt, *globals, *func_globals;

    printf("getting pyfunc %s\n", funcname);
    mod = PyEval_GetBuiltins();

    if (!mod) {
	    printf("cannot find module\n");
	    exit(0);
    }

    func_globals = PyDict_GetItemString(mod, "globals");
    if (!func_globals) {
	    printf("cannot find function globals\n");
	    exit(0);
    }

    if (!PyCallable_Check (func_globals)) {
	    printf("function not callable\n");
	    exit(0);
    }

    globals = PyObject_CallObject (func_globals, NULL);
    if (!globals) {
	    printf("cannot get globals\n");
	    exit(0);
    }

    func = PyDict_GetItemString (globals, funcname);
    if (!func) {
	    printf("cannot find function %s\n", funcname);
	    exit(0);
    }

    if (!PyCallable_Check (func)) {
	    printf("function not callable\n");
	    exit(0);
    }

    rslt = PyObject_CallObject (func, NULL);
    return rslt;
}



PyObject* _call_pyfunc_from_eip(void)
{
    PyObject  *mod,  *func, *rslt, *globals, *func_globals;
    char funcname[0x100];

    printf("getting pybloc %X\n", vmcpu.eip);
    sprintf(funcname, "bloc_%.8X", vmcpu.eip);
    printf("bloc name %s\n", funcname);

    mod = PyEval_GetBuiltins();

    if (!mod) {
	    printf("cannot find module\n");
	    exit(0);
    }
    func_globals = PyDict_GetItemString(mod, "globals");
    if (!func_globals) {
	    printf("cannot find function globals\n");
	    exit(0);
    }
    if (!PyCallable_Check (func_globals)) {
	    printf("function not callable\n");
	    exit(0);
    }
    globals = PyObject_CallObject (func_globals, NULL);
    if (!globals) {
	    printf("cannot get globals\n");
	    exit(0);
    }


    func = PyDict_GetItemString (globals, funcname);
    if (!func) {
	    printf("cannot find function %s\n", funcname);
	    exit(0);
    }
    if (!PyCallable_Check (func)) {
	    printf("function not callable\n");
	    exit(0);
    }
    rslt = PyObject_CallObject (func, NULL);
    return rslt;
}

PyObject* _vm_get_cpu_state(void)
{
	PyObject * o;
	o = PyString_FromStringAndSize((char*)&vmcpu, sizeof(vmcpu));
	return o;
}

PyObject*  _vm_set_cpu_state(PyObject * s_cpustate)
{
	unsigned int buf_size;
	Py_ssize_t length;
	char* buf;

	if(!PyString_Check(s_cpustate))
		RAISE(PyExc_TypeError,"arg must be str");

	buf_size = PyString_Size(s_cpustate);
	if (buf_size != sizeof(vmcpu))
		RAISE(PyExc_TypeError,"bad str len");

	PyString_AsStringAndSize(s_cpustate, (char**)&buf, &length);
	memcpy(&vmcpu, buf, length);
	return PyInt_FromLong((long)0);

}


PyObject* _vm_push_uint32_t(int val)
{
    vmcpu.esp-=4;
    MEM_WRITE(32, vmcpu.esp, val);

    return PyInt_FromLong((long)vmcpu.esp);
}


PyObject* _vm_pop_uint32_t(void)
{
    unsigned int val;

    val = MEM_LOOKUP(32, vmcpu.esp);
    vmcpu.esp+=4;

    return PyInt_FromLong((long)val);;
}

PyObject* _vm_set_mem(PyObject *addr, PyObject *item_str)
{
    unsigned int buf_size;
    char* buf_data;
    Py_ssize_t length;
    int ret = 0x1337;
    unsigned int val;

    struct memory_page_node * mpn;

    if (PyInt_Check(addr)){
	    val = (unsigned int)PyInt_AsLong(addr);
    }
    else if (PyLong_Check(addr)){
	    val = (unsigned int)PyInt_AsUnsignedLongLongMask(addr);
    }
    else{
	    RAISE(PyExc_TypeError,"arg1 must be int");
    }


    if(!PyString_Check(item_str))
       RAISE(PyExc_TypeError,"arg must be str");

    buf_size = PyString_Size(item_str);
    PyString_AsStringAndSize(item_str, &buf_data, &length);

    printf("set addr: %X (len %X)\n", val, (unsigned int)length);

    mpn = get_memory_page_from_address(val);
    memcpy(mpn->ad_hp + (val-mpn->ad), buf_data, buf_size);

    return PyInt_FromLong((long)ret);
}


PyObject* _vm_set_mem_access(PyObject *addr, PyObject *access)
{
    int ret = 0x1337beef;
    unsigned int page_addr;
    unsigned int page_access;

    struct memory_page_node * mpn;

    if (PyInt_Check(addr)){
	    page_addr = (unsigned int)PyInt_AsLong(addr);
    }
    else if (PyLong_Check(addr)){
	    page_addr = (unsigned int)PyInt_AsUnsignedLongLongMask(addr);
    }
    else{
	    RAISE(PyExc_TypeError,"arg1 must be int");
    }

    if (PyInt_Check(access)){
	    page_access = (unsigned int)PyInt_AsLong(access);
    }
    else if (PyLong_Check(access)){
	    page_access = (unsigned int)PyInt_AsUnsignedLongLongMask(access);
    }
    else{
	    RAISE(PyExc_TypeError,"arg2 must be int");
    }

    mpn = get_memory_page_from_address(page_addr);
    mpn->access = page_access;
    return PyInt_FromLong((long)ret);
}


PyObject* _vm_get_str(PyObject *addr, PyObject *item_len)
{
    unsigned int buf_addr;
    unsigned int buf_len;
    PyObject *obj_out;
    struct memory_page_node * mpn;
    char* buf_out;
    char * addr_tmp;
    char* addr_out;
    int off;
    unsigned int l;
    unsigned int my_size;

    if (PyInt_Check(addr)){
	    buf_addr = (unsigned int)PyInt_AsLong(addr);
    }
    else if (PyLong_Check(addr)){
	    buf_addr = (unsigned int)PyInt_AsUnsignedLongLongMask(addr);
    }
    else{
	    RAISE(PyExc_TypeError,"arg1 must be int");
    }
    if (PyInt_Check(item_len)){
	    buf_len = (unsigned int)PyInt_AsLong(item_len);
    }
    else if (PyLong_Check(item_len)){
	    buf_len = (unsigned int)PyInt_AsUnsignedLongLongMask(item_len);
    }
    else{
	    RAISE(PyExc_TypeError,"arg must be int");
    }

    my_size = buf_len;
    buf_out = malloc(buf_len);
    if (!buf_out){
	    printf("cannot alloc read\n");
	    exit(-1);
    }

    addr_out = buf_out;

    /* read is multiple page wide */
    while (my_size){
	    mpn = get_memory_page_from_address(buf_addr);
	    if (!mpn){
		    printf("cannot find page off %X\n", buf_addr);
		    return 0;
	    }


	    off = buf_addr - mpn->ad;
	    addr_tmp = &((char*)mpn->ad_hp)[off];

	    l = MIN(my_size, mpn->size - off);
	    memcpy(addr_out, addr_tmp, l);
	    my_size -= l;
	    addr_out +=l;
	    buf_addr +=l;
    }

    obj_out = PyString_FromStringAndSize(buf_out, buf_len);
    free(buf_out);
    return obj_out;
}

PyObject * dump_gpregs_py(PyObject* self, PyObject* args)
{
	dump_gpregs();
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_get_last_write_ad(PyObject* self, PyObject* args)
{
	return PyInt_FromLong((long)vmcpu.vm_last_write_ad);
}

PyObject* vm_get_last_write_size(PyObject* self, PyObject* args)
{
	return PyInt_FromLong((long)vmcpu.vm_last_write_size);
}


PyObject* vm_reset_exception(PyObject* self, PyObject* args)
{
	vmcpu.vm_exception_flags = 0;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_get_exception(PyObject* self, PyObject* args)
{
	return PyInt_FromLong((long)vmcpu.vm_exception_flags);
}

PyObject * vm_init_regs(PyObject* self, PyObject* args)
{
    _vm_init_regs();
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* vm_push_uint32_t(PyObject* self, PyObject *args)
{
    PyObject* p;
    int item;
    if (!PyArg_ParseTuple(args, "I", &item))
	    return NULL;
    p = _vm_push_uint32_t(item);
    return p;
}


PyObject* vm_pop_uint32_t(PyObject* self, PyObject* args)
{
    PyObject* p;
    p = _vm_pop_uint32_t();
    return p;
}

PyObject* vm_set_mem(PyObject* self, PyObject* args)
{
    PyObject* p;
    PyObject *addr;
    PyObject *item_str;
    if (!PyArg_ParseTuple(args, "OO", &addr, &item_str))
	    return NULL;

    p = _vm_set_mem(addr, item_str);
    return p;
}

PyObject* vm_set_mem_access(PyObject* self, PyObject* args)
{
    PyObject* p;
    PyObject *addr;
    PyObject *access;
    if (!PyArg_ParseTuple(args, "OO", &addr, &access))
	    return NULL;

    p = _vm_set_mem_access(addr, access);
    return p;
}


PyObject* vm_get_str(PyObject* self, PyObject* args)
{
    PyObject* p;
    PyObject *item;
    PyObject *item_len;
    if (!PyArg_ParseTuple(args, "OO", &item, &item_len))
	    return NULL;

    p = _vm_get_str(item, item_len);
    return p;
}


PyObject* vm_get_gpreg(PyObject* self, PyObject* args)
{
    PyObject* p;
    p = _vm_get_gpreg();
    return p;
}

PyObject* vm_set_gpreg(PyObject *self, PyObject *args)
{
	PyObject* dict;
	if (!PyArg_ParseTuple(args, "O", &dict))
		return NULL;
	_vm_set_gpreg(dict);
	Py_INCREF(Py_None);
	return Py_None;

}

PyObject* init_memory_page_pool_py(PyObject* self, PyObject* args)
{
    init_memory_page_pool();
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* init_code_bloc_pool_py(PyObject* self, PyObject* args)
{
    init_code_bloc_pool();
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject* vm_add_memory_page(PyObject* self, PyObject* args)
{
	PyObject *item;
	PyObject *access;
	PyObject *item_str;
	PyObject* p;
	if (!PyArg_ParseTuple(args, "OOO", &item, &access, &item_str))
		return NULL;
	p = _vm_add_memory_page(item, access, item_str);
	return p;
}



PyObject* dump_memory_page_pool_py(PyObject* self, PyObject* args)
{
     dump_memory_page_pool();
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject* vm_get_all_memory(PyObject* self, PyObject* args)
{
	PyObject *o;
	o = _vm_get_all_memory();
	return o;
}


PyObject* reset_memory_page_pool_py(PyObject* self, PyObject* args)
{
    reset_memory_page_pool();
    Py_INCREF(Py_None);
    return Py_None;

}

PyObject* reset_code_bloc_pool_py(PyObject* self, PyObject* args)
{
    reset_code_bloc_pool();
    Py_INCREF(Py_None);
    return Py_None;

}


PyObject* call_pyfunc_from_globals(PyObject* self, PyObject* args)
{
	PyObject* p;
	char* funcname;
	if (!PyArg_ParseTuple(args, "s", &funcname))
	    return NULL;

	p = _call_pyfunc_from_globals(funcname);
	return p;
}


PyObject* _vm_add_code_bloc(PyObject* self, PyObject* args)
{
	PyObject *item1;
	PyObject *item2;
    int ret = 0x1337beef;
    unsigned int ad_start, ad_stop, ad_code = 0;

    struct code_bloc_node * cbp;

    if (!PyArg_ParseTuple(args, "OO", &item1, &item2))
	    return NULL;


    if (PyInt_Check(item1)){
	    ad_start = (unsigned int)PyInt_AsLong(item1);
    }
    else if (PyLong_Check(item1)){
	    ad_start = (unsigned int)PyInt_AsUnsignedLongLongMask(item1);
    }
    else{
	    RAISE(PyExc_TypeError,"arg1 must be int");
    }

    if (PyInt_Check(item2)){
	    ad_stop = (unsigned int)PyInt_AsLong(item2);
    }
    else if (PyLong_Check(item2)){
	    ad_stop = (unsigned int)PyInt_AsUnsignedLongLongMask(item2);
    }
    else{
	    RAISE(PyExc_TypeError,"arg2 must be int");
    }

    cbp = create_code_bloc_node(ad_start, ad_stop);
    cbp->ad_start = ad_start;
    cbp->ad_stop = ad_stop;
    cbp->ad_code = ad_code;
    add_code_bloc(cbp);
    return PyInt_FromLong((long)ret);
}


PyObject* vm_add_code_bloc(PyObject *item1, PyObject *item2)
{
	PyObject* p;
	p = _vm_add_code_bloc(item1, item2);
	return p;
}

PyObject* dump_code_bloc_pool_py(void)
{
	dump_code_bloc_pool();
	Py_INCREF(Py_None);
	return Py_None;

}



PyObject* vm_get_cpu_state(void)
{
	PyObject* o;
	o = _vm_get_cpu_state();
	return o;
}

PyObject*  vm_set_cpu_state(PyObject * s_cpustate)
{
	PyObject *o;
	o = _vm_set_cpu_state(s_cpustate);
	return o;
}



unsigned int get_memory_page_max_address_py(void)
{
	unsigned int ret;
	ret = _get_memory_page_max_address_py();
	return ret;
}

PyObject * vm_get_memory_page_max_address(PyObject* self, PyObject* args)
{
	PyObject* v;
	unsigned int tmp;

	tmp = get_memory_page_max_address_py();
	v = PyInt_FromLong((long)tmp);
	return v;
}

unsigned int get_memory_page_max_user_address_py(void)
{
	unsigned int ret;
	ret = _get_memory_page_max_user_address_py();
	return ret;
}


unsigned int get_memory_page_from_min_ad_py(unsigned int size)
{
	unsigned int ret;
	ret = _get_memory_page_from_min_ad_py(size);
	return ret;

}


PyObject* _vm_exec_blocs(PyObject* self, PyObject* args)
{
	PyObject* b;
	PyObject* module;
	PyObject* func;
	PyObject* meip;
	unsigned long tmp;

	PyObject* my_eip;
	PyObject* known_blocs;
	PyObject* e;

	if (!PyArg_ParseTuple(args, "OO", &my_eip, &known_blocs))
		return NULL;

	if(!PyDict_Check(known_blocs))
		RAISE(PyExc_TypeError, "arg must be dict");

	if (PyInt_Check(my_eip)){
		tmp = (unsigned long)PyInt_AsLong(my_eip);
	}
	else if (PyLong_Check(my_eip)){
		tmp = (unsigned long)PyInt_AsUnsignedLongLongMask(my_eip);
	}
	else{
		RAISE(PyExc_TypeError,"arg1 must be int");
	}
	meip = PyLong_FromUnsignedLong((unsigned long)tmp);
	while (1){
		b = PyDict_GetItem(known_blocs, meip);
		if (b == NULL)
			return meip;

		module = PyObject_GetAttrString(b, "module_c");
		if (module == NULL){
			printf("assert eip module_c in pyobject\n");
			exit(0);
		}
		func = PyObject_GetAttrString(module, "func");
		if (func == NULL){
			printf("assert func module_c in pyobject\n");
			exit(0);
		}

		Py_DECREF(module);
		if (!PyCallable_Check (func)) {
			printf("function not callable\n");
			exit(0);
		}
		Py_DECREF(meip);
		meip = PyObject_CallObject (func, NULL);

		Py_DECREF(func);
		e = PyErr_Occurred ();
		if (e){
			printf("exception\n");
			return meip;
		}

		if (vmcpu.vm_exception_flags)
			return meip;

	}
}


PyObject* vm_exec_blocs(PyObject* self, PyObject* args)
{
	PyObject* my_eip;
	my_eip = _vm_exec_blocs(self, args);
	return my_eip;
}



PyObject* vm_exec_bloc(PyObject* self, PyObject* args)
{
	PyObject* b;
	PyObject* module;
	PyObject* func;
	PyObject* meip;
	unsigned int tmp;

	PyObject* my_eip;
	PyObject* known_blocs;
	PyObject* e;

	if (!PyArg_ParseTuple(args, "OO", &my_eip, &known_blocs))
		return NULL;


	if (PyInt_Check(my_eip)){
		tmp = (unsigned int)PyInt_AsLong(my_eip);
	}
	else if (PyLong_Check(my_eip)){
		tmp = (unsigned int)PyInt_AsUnsignedLongLongMask(my_eip);
	}
	else{
		RAISE(PyExc_TypeError,"arg1 must be int");
	}

	meip = PyInt_FromLong((long)tmp);
	b = PyDict_GetItem(known_blocs, my_eip);
	if (b == NULL)
		return meip;
	module = PyObject_GetAttrString(b, "module_c");
	if (module == NULL)
		return meip;
	func = PyObject_GetAttrString(module, "func");
	if (func == NULL)
		return meip;
	Py_DECREF(module);
	if (!PyCallable_Check (func)) {
		printf("function not callable\n");
		exit(0);
	}
	Py_DECREF(meip);
	meip = PyObject_CallObject (func, NULL);

	Py_DECREF(func);
	e = PyErr_Occurred ();
	if (e){
		printf("exception\n");
		return meip;
	}

	return meip;
}

static PyObject *CodenatError;


static PyMethodDef CodenatMethods[] = {
    {"vm_init_regs",  vm_init_regs, METH_VARARGS,
     "init regs vm."},
    {"vm_push_uint32_t", vm_push_uint32_t, METH_VARARGS,
     "push on vm stack"},
    {"dump_gpregs_py", dump_gpregs_py, METH_VARARGS,
     "x"},


    {"vm_push_uint32_t", vm_push_uint32_t, METH_VARARGS,
     "x"},
    {"vm_pop_uint32_t",vm_pop_uint32_t, METH_VARARGS,
     "X"},
    {"vm_get_gpreg", vm_get_gpreg, METH_VARARGS,
     "X"},
    {"vm_set_gpreg",vm_set_gpreg, METH_VARARGS,
     "X"},
    {"vm_init_regs",vm_init_regs, METH_VARARGS,
     "X"},
    {"dump_gpregs_py", dump_gpregs_py, METH_VARARGS,
     "X"},

    {"init_memory_page_pool_py", init_memory_page_pool_py, METH_VARARGS,
     "X"},
    {"init_code_bloc_pool_py",init_code_bloc_pool_py, METH_VARARGS,
     "X"},
    {"vm_set_mem_access", vm_set_mem_access, METH_VARARGS,
     "X"},
    {"vm_set_mem", vm_set_mem, METH_VARARGS,
     "X"},
    {"vm_add_code_bloc",vm_add_code_bloc, METH_VARARGS,
     "X"},
    {"vm_exec_bloc",vm_exec_bloc, METH_VARARGS,
     "X"},
    {"vm_exec_blocs",vm_exec_blocs, METH_VARARGS,
     "X"},
    {"vm_get_str", vm_get_str, METH_VARARGS,
     "X"},
    {"vm_add_memory_page",vm_add_memory_page, METH_VARARGS,
     "X"},
    {"vm_reset_exception", vm_reset_exception, METH_VARARGS,
     "X"},
    {"dump_memory_page_pool_py", dump_memory_page_pool_py, METH_VARARGS,
     "X"},
    {"vm_get_all_memory",vm_get_all_memory, METH_VARARGS,
     "X"},
    {"reset_memory_page_pool_py", reset_memory_page_pool_py, METH_VARARGS,
     "X"},
    {"reset_code_bloc_pool_py", reset_code_bloc_pool_py, METH_VARARGS,
     "X"},
    {"call_pyfunc_from_globals",call_pyfunc_from_globals, METH_VARARGS,
     "X"},

    {"vm_get_exception",vm_get_exception, METH_VARARGS,
     "X"},
    {"vm_get_exception",vm_get_exception, METH_VARARGS,
     "X"},
    {"vm_get_last_write_ad", vm_get_last_write_ad, METH_VARARGS,
     "X"},
    {"vm_get_last_write_size",vm_get_last_write_size, METH_VARARGS,
     "X"},
    {"vm_get_memory_page_max_address",vm_get_memory_page_max_address, METH_VARARGS,
     "X"},

    {NULL, NULL, 0, NULL}        /* Sentinel */

};


PyMODINIT_FUNC
initlibcodenat_interface(void)
{
    PyObject *m;

    m = Py_InitModule("libcodenat_interface", CodenatMethods);
    if (m == NULL)
	    return;

    CodenatError = PyErr_NewException("codenat.error", NULL, NULL);
    Py_INCREF(CodenatError);
    PyModule_AddObject(m, "error", CodenatError);
}

