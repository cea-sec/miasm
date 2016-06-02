#include <Python.h>
#include "../JitCore.h"
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include "../queue.h"
#include "../vm_mngr.h"
#include "../vm_mngr_py.h"
#include "JitCore_ebc.h"

reg_dict gpreg_dict[] = { {.name = "IP", .offset = offsetof(vm_cpu_t, IP)},
			  {.name = "R0", .offset = offsetof(vm_cpu_t, R0)},
			  {.name = "R1", .offset = offsetof(vm_cpu_t, R1)},
			  {.name = "R2", .offset = offsetof(vm_cpu_t, R2)},
			  {.name = "R3", .offset = offsetof(vm_cpu_t, R3)},
			  {.name = "R4", .offset = offsetof(vm_cpu_t, R4)},
			  {.name = "R5", .offset = offsetof(vm_cpu_t, R5)},
			  {.name = "R6", .offset = offsetof(vm_cpu_t, R6)},
			  {.name = "R7", .offset = offsetof(vm_cpu_t, R7)},
			  {.name = "cf", .offset = offsetof(vm_cpu_t, cf)},
			  {.name = "sf", .offset = offsetof(vm_cpu_t, sf)},
};

/************************** JitCpu object **************************/

PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(IP);
    get_reg(R0);
    get_reg(R1);
    get_reg(R2);
    get_reg(R3);
    get_reg(R4);
    get_reg(R5);
    get_reg(R6);
    get_reg(R7);

    get_reg(cf);
    get_reg(sf);

    return dict;
}

PyObject* cpu_set_gpreg(JitCpu* self, PyObject *args)
{
    PyObject* dict;
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    uint64_t val;
    unsigned int i, found;

    if (!PyArg_ParseTuple(args, "O", &dict))
	    return NULL;
    if(!PyDict_Check(dict))
	    RAISE(PyExc_TypeError, "arg must be dict");
    while(PyDict_Next(dict, &pos, &d_key, &d_value)){
	    if(!PyString_Check(d_key))
		    RAISE(PyExc_TypeError, "key must be str");

	    PyGetInt(d_value, val);

	    found = 0;
	    for (i=0; i < sizeof(gpreg_dict)/sizeof(reg_dict); i++){
		    if (strcmp(PyString_AsString(d_key), gpreg_dict[i].name))
			    continue;
		    *((uint32_t*)(((char*)(self->cpu)) + gpreg_dict[i].offset)) = val;
		    found = 1;
		    break;
	    }

	    if (found)
		    continue;
	    fprintf(stderr, "unkown key: %s\n", PyString_AsString(d_key));
	    RAISE(PyExc_ValueError, "unkown reg");
    }
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject * cpu_init_regs(JitCpu* self)
{
	memset(self->cpu, 0, sizeof(vm_cpu_t));

	Py_INCREF(Py_None);
	return Py_None;

}

void dump_gpregs(vm_cpu_t* vmcpu)
{
	printf(" IP  %.16"PRIx64, vmcpu->IP);
	printf(" cf  %.16"PRIx64, vmcpu->cf);
	printf(" sf  %.16"PRIx64, vmcpu->sf);
	printf(" \n");
	printf(" R0  %.16"PRIx64, vmcpu->R0);
	printf(" R1  %.16"PRIx64, vmcpu->R1);
	printf(" R2  %.16"PRIx64, vmcpu->R2);
	printf(" R3  %.16"PRIx64, vmcpu->R3);
	printf(" \n");
	printf(" R4  %.16"PRIx64, vmcpu->R4);
	printf(" R5  %.16"PRIx64, vmcpu->R5);
	printf(" R6  %.16"PRIx64, vmcpu->R6);
	printf(" R7  %.16"PRIx64, vmcpu->R7);
	printf(" \n");
}

PyObject * cpu_dump_gpregs(JitCpu* self, PyObject* args)
{
	vm_cpu_t* vmcpu;

	vmcpu = self->cpu;
	dump_gpregs(vmcpu);
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* cpu_set_exception(JitCpu* self, PyObject* args)
{
	PyObject *item1;
	uint64_t i;

	if (!PyArg_ParseTuple(args, "O", &item1))
		return NULL;

	PyGetInt(item1, i);

	((vm_cpu_t*)self->cpu)->exception_flags = i;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* cpu_get_exception(JitCpu* self, PyObject* args)
{
	return PyLong_FromUnsignedLongLong((uint64_t)(((vm_cpu_t*)self->cpu)->exception_flags));
}

void check_automod(JitCpu* jitcpu, uint64_t addr, uint64_t size)
{
	PyObject *result;

	if (!(((VmMngr*)jitcpu->pyvm)->vm_mngr.exception_flags & EXCEPT_CODE_AUTOMOD))
		return;
	result = PyObject_CallMethod(jitcpu->jitter, "automod_cb", "LL", addr, size);
	Py_DECREF(result);

}

void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src)
{
	vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
	check_automod(jitcpu, addr, 8);
}

void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src)
{
	vm_MEM_WRITE_16(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
	check_automod(jitcpu, addr, 16);
}

void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src)
{
	vm_MEM_WRITE_32(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
	check_automod(jitcpu, addr, 32);
}

void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src)
{
	vm_MEM_WRITE_64(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
	check_automod(jitcpu, addr, 64);
}

PyObject* vm_set_mem(JitCpu *self, PyObject* args)
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

       ret = vm_write_mem(&(((VmMngr*)self->pyvm)->vm_mngr), addr, buffer, size);
       if (ret < 0)
	       RAISE(PyExc_TypeError,"arg must be str");
       check_automod(self, addr, size*8);

       Py_INCREF(Py_None);
       return Py_None;
}

static PyMemberDef JitCpu_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef JitCpu_methods[] = {
	{"init_regs", (PyCFunction)cpu_init_regs, METH_NOARGS,
	 "X"},
	{"dump_gpregs", (PyCFunction)cpu_dump_gpregs, METH_NOARGS,
	 "X"},
	{"get_gpreg", (PyCFunction)cpu_get_gpreg, METH_NOARGS,
	 "X"},
	{"set_gpreg", (PyCFunction)cpu_set_gpreg, METH_VARARGS,
	 "X"},
	{"get_exception", (PyCFunction)cpu_get_exception, METH_VARARGS,
	 "X"},
	{"set_exception", (PyCFunction)cpu_set_exception, METH_VARARGS,
	 "X"},
	{"set_mem", (PyCFunction)vm_set_mem, METH_VARARGS,
	 "X"},
	{"get_mem", (PyCFunction)vm_get_mem, METH_VARARGS,
	 "X"},
	{NULL}  /* Sentinel */
};

static int
JitCpu_init(JitCpu *self, PyObject *args, PyObject *kwds)
{
	self->cpu = malloc(sizeof(vm_cpu_t));
	if (self->cpu == NULL) {
		fprintf(stderr, "cannot alloc vm_cpu_t\n");
		exit(0);
	}
	return 0;
}

getset_reg_u64(IP);
getset_reg_u64(R0);
getset_reg_u64(R1);
getset_reg_u64(R2);
getset_reg_u64(R3);
getset_reg_u64(R4);
getset_reg_u64(R5);
getset_reg_u64(R6);
getset_reg_u64(R7);
getset_reg_u64(cf);
getset_reg_u64(sf);

PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;
    get_reg_off(exception_flags);
    get_reg_off(exception_flags_new);
    get_reg_off(IP);
    get_reg_off(R0);
    get_reg_off(R1);
    get_reg_off(R2);
    get_reg_off(R3);
    get_reg_off(R4);
    get_reg_off(R5);
    get_reg_off(R6);
    get_reg_off(R7);
    get_reg_off(IP_new);
    get_reg_off(R0_new);
    get_reg_off(R1_new);
    get_reg_off(R2_new);
    get_reg_off(R3_new);
    get_reg_off(R4_new);
    get_reg_off(R5_new);
    get_reg_off(R6_new);
    get_reg_off(R7_new);
    get_reg_off(cf);
    get_reg_off(sf);
    get_reg_off(cf_new);
    get_reg_off(sf_new);

    get_reg_off(pfmem08_0);
    get_reg_off(pfmem16_0);
    get_reg_off(pfmem32_0);
    get_reg_off(pfmem64_0);

    return dict;
}

static PyGetSetDef JitCpu_getseters[] = {
    {"vmmngr",
     (getter)JitCpu_get_vmmngr, (setter)JitCpu_set_vmmngr,
     "vmmngr",
     NULL},

    {"jitter",
     (getter)JitCpu_get_jitter, (setter)JitCpu_set_jitter,
     "jitter",
     NULL},

    {"IP" , (getter)JitCpu_get_IP      , (setter)JitCpu_set_IP     , "IP" , NULL},
    {"R0" , (getter)JitCpu_get_R0      , (setter)JitCpu_set_R0     , "R0" , NULL},
    {"R1" , (getter)JitCpu_get_R1      , (setter)JitCpu_set_R1     , "R1" , NULL},
    {"R2" , (getter)JitCpu_get_R2      , (setter)JitCpu_set_R2     , "R2" , NULL},
    {"R3" , (getter)JitCpu_get_R3      , (setter)JitCpu_set_R3     , "R3" , NULL},
    {"R4" , (getter)JitCpu_get_R4      , (setter)JitCpu_set_R4     , "R4" , NULL},
    {"R5" , (getter)JitCpu_get_R5      , (setter)JitCpu_set_R5     , "R5" , NULL},
    {"R6" , (getter)JitCpu_get_R6      , (setter)JitCpu_set_R6     , "R6" , NULL},
    {"R7" , (getter)JitCpu_get_R7      , (setter)JitCpu_set_R7     , "R7" , NULL},
    {"cf" , (getter)JitCpu_get_cf      , (setter)JitCpu_set_cf     , "cf" , NULL},
    {"sf" , (getter)JitCpu_get_sf      , (setter)JitCpu_set_sf     , "sf" , NULL},

    {NULL}  /* Sentinel */
};

static PyTypeObject JitCpuType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "JitCore_ebc.JitCpu",   /*tp_name*/
    sizeof(JitCpu),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)JitCpu_dealloc,/*tp_dealloc*/
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
    "JitCpu objects",          /* tp_doc */
    0,			       /* tp_traverse */
    0,			       /* tp_clear */
    0,			       /* tp_richcompare */
    0,			       /* tp_weaklistoffset */
    0,			       /* tp_iter */
    0,			       /* tp_iternext */
    JitCpu_methods,            /* tp_methods */
    JitCpu_members,            /* tp_members */
    JitCpu_getseters,          /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)JitCpu_init,     /* tp_init */
    0,                         /* tp_alloc */
    JitCpu_new,                /* tp_new */
};

static PyMethodDef JitCore_ebc_Methods[] = {

	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};

static PyObject *JitCore_ebc_Error;

PyMODINIT_FUNC
initJitCore_ebc(void)
{
    PyObject *m;

    if (PyType_Ready(&JitCpuType) < 0)
	return;

    m = Py_InitModule("JitCore_ebc", JitCore_ebc_Methods);
    if (m == NULL)
	    return;

    JitCore_ebc_Error = PyErr_NewException("JitCore_ebc.error", NULL, NULL);
    Py_INCREF(JitCore_ebc_Error);
    PyModule_AddObject(m, "error", JitCore_ebc_Error);

    Py_INCREF(&JitCpuType);
    PyModule_AddObject(m, "JitCpu", (PyObject *)&JitCpuType);
}

