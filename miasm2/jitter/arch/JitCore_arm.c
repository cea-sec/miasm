#include <Python.h>
#include "JitCore.h"
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include "JitCore_arm.h"

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}

typedef struct _reg_dict{
    char* name;
    unsigned long offset;
} reg_dict;


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

reg_dict gpreg_dict[] = { {.name = "R0", .offset = offsetof(vm_cpu_t, R0)},
			  {.name = "R1", .offset = offsetof(vm_cpu_t, R1)},
			  {.name = "R2", .offset = offsetof(vm_cpu_t, R2)},
			  {.name = "R3", .offset = offsetof(vm_cpu_t, R3)},
			  {.name = "R4", .offset = offsetof(vm_cpu_t, R4)},
			  {.name = "R5", .offset = offsetof(vm_cpu_t, R5)},
			  {.name = "R6", .offset = offsetof(vm_cpu_t, R6)},
			  {.name = "R7", .offset = offsetof(vm_cpu_t, R7)},
			  {.name = "R8", .offset = offsetof(vm_cpu_t, R8)},
			  {.name = "R9", .offset = offsetof(vm_cpu_t, R9)},
			  {.name = "R10", .offset = offsetof(vm_cpu_t, R10)},
			  {.name = "R11", .offset = offsetof(vm_cpu_t, R11)},
			  {.name = "R12", .offset = offsetof(vm_cpu_t, R12)},
			  {.name = "SP", .offset = offsetof(vm_cpu_t, SP)},
			  {.name = "LR", .offset = offsetof(vm_cpu_t, LR)},
			  {.name = "PC", .offset = offsetof(vm_cpu_t, PC)},

			  {.name = "zf", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "nf", .offset = offsetof(vm_cpu_t, nf)},
			  {.name = "of", .offset = offsetof(vm_cpu_t, of)},
			  {.name = "cf", .offset = offsetof(vm_cpu_t, cf)},
};

/************************** JitCpu object **************************/

typedef struct {
	PyObject_HEAD
	PyObject *cpu; /* cpu */
	vm_cpu_t vmcpu;
} JitCpu;



#define get_reg(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)self->vmcpu.reg); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);



PyObject* vm_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(R0);
    get_reg(R1);
    get_reg(R2);
    get_reg(R3);
    get_reg(R4);
    get_reg(R5);
    get_reg(R6);
    get_reg(R7);
    get_reg(R8);
    get_reg(R9);
    get_reg(R10);
    get_reg(R11);
    get_reg(R12);
    get_reg(SP);
    get_reg(LR);
    get_reg(PC);

    get_reg(zf);
    get_reg(nf);
    get_reg(of);
    get_reg(cf);

    return dict;
}

PyObject* _vm_set_gpreg(JitCpu* self, PyObject *dict)
{
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    uint64_t val;
    unsigned int i, found;

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
		    *((uint32_t*)(((char*)&(self->vmcpu)) + gpreg_dict[i].offset)) = val;
		    found = 1;
		    break;
	    }

	    if (found)
		    continue;
	    fprintf(stderr, "unkown key: %s\n", PyString_AsString(d_key));
	    RAISE(PyExc_ValueError, "unkown reg");
    }
    return NULL;
}

PyObject* vm_set_gpreg(JitCpu* self, PyObject *args)
{
	PyObject* dict;
	if (!PyArg_ParseTuple(args, "O", &dict))
		return NULL;
	_vm_set_gpreg(self, dict);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject* vm_set_exception(JitCpu* self, PyObject* args)
{
	PyObject *item1;
	uint64_t i;

	if (!PyArg_ParseTuple(args, "O", &item1))
		return NULL;

	PyGetInt(item1, i);

	self->vmcpu.exception_flags = i;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* vm_get_exception(JitCpu* self, PyObject* args)
{
	return PyLong_FromUnsignedLongLong((uint64_t)self->vmcpu.exception_flags);
}


PyObject * vm_init_regs(JitCpu* self)
{
	memset(&self->vmcpu, 0, sizeof(vm_cpu_t));

	Py_INCREF(Py_None);
	return Py_None;

}

void dump_gpregs(vm_cpu_t* vmcpu)
{
	printf("R0 %.16"PRIX32" R1 %.16"PRIX32" R2 %.16"PRIX32" R3 %.16"PRIX32"\n",
	       vmcpu->R0, vmcpu->R1, vmcpu->R2, vmcpu->R3);
	printf("R4 %.16"PRIX32" R5 %.16"PRIX32" R6 %.16"PRIX32" R7 %.16"PRIX32"\n",
	       vmcpu->R4, vmcpu->R5, vmcpu->R6, vmcpu->R7);
	printf("R8 %.16"PRIX32" R9 %.16"PRIX32" R10 %.16"PRIX32" R11 %.16"PRIX32"\n",
	       vmcpu->R8, vmcpu->R9, vmcpu->R10, vmcpu->R11);
	printf("R12 %.16"PRIX32" SP %.16"PRIX32" LR %.16"PRIX32" PC %.16"PRIX32"\n",
	       vmcpu->R12, vmcpu->SP, vmcpu->LR, vmcpu->PC);
	printf("zf %.16"PRIX32" nf %.16"PRIX32" of %.16"PRIX32" cf %.16"PRIX32"\n",
	       vmcpu->zf, vmcpu->nf, vmcpu->of, vmcpu->cf);
}


PyObject * vm_dump_gpregs(JitCpu* self, PyObject* args)
{
	vm_cpu_t* vmcpu;

	vmcpu = &self->vmcpu;
	dump_gpregs(vmcpu);
	Py_INCREF(Py_None);
	return Py_None;
}



static void
JitCpu_dealloc(JitCpu* self)
{
    self->ob_type->tp_free((PyObject*)self);
}


static PyObject *
JitCpu_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    JitCpu *self;

    self = (JitCpu *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

static PyObject *
JitCpu_get_cpu(JitCpu *self, void *closure)
{
	return PyLong_FromUnsignedLongLong((uint64_t)&(self->vmcpu));
}

static int
JitCpu_set_cpu(JitCpu *self, PyObject *value, void *closure)
{
	PyErr_SetString(PyExc_TypeError, "immutable cpu");
	return -1;
}

static PyMemberDef JitCpu_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef JitCpu_methods[] = {
	{"vm_init_regs", (PyCFunction)vm_init_regs, METH_NOARGS,
	 "X"},
	{"vm_dump_gpregs", (PyCFunction)vm_dump_gpregs, METH_NOARGS,
	 "X"},
	{"vm_get_gpreg", (PyCFunction)vm_get_gpreg, METH_NOARGS,
	 "X"},
	{"vm_set_gpreg", (PyCFunction)vm_set_gpreg, METH_VARARGS,
	 "X"},
	{"vm_get_exception", (PyCFunction)vm_get_exception, METH_VARARGS,
	 "X"},
	{"vm_set_exception", (PyCFunction)vm_set_exception, METH_VARARGS,
	 "X"},
	{NULL}  /* Sentinel */
};

static int
JitCpu_init(JitCpu *self, PyObject *args, PyObject *kwds)
{
	return 0;
}

getset_reg_u32(R0);
getset_reg_u32(R1);
getset_reg_u32(R2);
getset_reg_u32(R3);
getset_reg_u32(R4);
getset_reg_u32(R5);
getset_reg_u32(R6);
getset_reg_u32(R7);
getset_reg_u32(R8);
getset_reg_u32(R9);
getset_reg_u32(R10);
getset_reg_u32(R11);
getset_reg_u32(R12);
getset_reg_u32(SP);
getset_reg_u32(LR);
getset_reg_u32(PC);

getset_reg_u32(zf);
getset_reg_u32(nf);
getset_reg_u32(of);
getset_reg_u32(cf);



#define get_reg_off(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)offsetof(vm_cpu_t, reg)); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);

PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg_off(exception_flags);
    get_reg_off(exception_flags_new);


    get_reg_off(R0);
    get_reg_off(R1);
    get_reg_off(R2);
    get_reg_off(R3);
    get_reg_off(R4);
    get_reg_off(R5);
    get_reg_off(R6);
    get_reg_off(R7);
    get_reg_off(R8);
    get_reg_off(R9);
    get_reg_off(R10);
    get_reg_off(R11);
    get_reg_off(R12);
    get_reg_off(SP);
    get_reg_off(LR);
    get_reg_off(PC);

    get_reg_off(R0_new);
    get_reg_off(R1_new);
    get_reg_off(R2_new);
    get_reg_off(R3_new);
    get_reg_off(R4_new);
    get_reg_off(R5_new);
    get_reg_off(R6_new);
    get_reg_off(R7_new);
    get_reg_off(R8_new);
    get_reg_off(R9_new);
    get_reg_off(R10_new);
    get_reg_off(R11_new);
    get_reg_off(R12_new);
    get_reg_off(SP_new);
    get_reg_off(LR_new);
    get_reg_off(PC_new);

	/* eflag */
    get_reg_off(zf);
    get_reg_off(nf);
    get_reg_off(of);
    get_reg_off(cf);

    get_reg_off(zf_new);
    get_reg_off(nf_new);
    get_reg_off(of_new);
    get_reg_off(cf_new);


    get_reg_off(pfmem08_0);
    get_reg_off(pfmem08_1);
    get_reg_off(pfmem08_2);
    get_reg_off(pfmem08_3);
    get_reg_off(pfmem08_4);
    get_reg_off(pfmem08_5);
    get_reg_off(pfmem08_6);
    get_reg_off(pfmem08_7);
    get_reg_off(pfmem08_8);
    get_reg_off(pfmem08_9);
    get_reg_off(pfmem08_10);
    get_reg_off(pfmem08_11);
    get_reg_off(pfmem08_12);
    get_reg_off(pfmem08_13);
    get_reg_off(pfmem08_14);
    get_reg_off(pfmem08_15);
    get_reg_off(pfmem08_16);
    get_reg_off(pfmem08_17);
    get_reg_off(pfmem08_18);
    get_reg_off(pfmem08_19);


    get_reg_off(pfmem16_0);
    get_reg_off(pfmem16_1);
    get_reg_off(pfmem16_2);
    get_reg_off(pfmem16_3);
    get_reg_off(pfmem16_4);
    get_reg_off(pfmem16_5);
    get_reg_off(pfmem16_6);
    get_reg_off(pfmem16_7);
    get_reg_off(pfmem16_8);
    get_reg_off(pfmem16_9);
    get_reg_off(pfmem16_10);
    get_reg_off(pfmem16_11);
    get_reg_off(pfmem16_12);
    get_reg_off(pfmem16_13);
    get_reg_off(pfmem16_14);
    get_reg_off(pfmem16_15);
    get_reg_off(pfmem16_16);
    get_reg_off(pfmem16_17);
    get_reg_off(pfmem16_18);
    get_reg_off(pfmem16_19);


    get_reg_off(pfmem32_0);
    get_reg_off(pfmem32_1);
    get_reg_off(pfmem32_2);
    get_reg_off(pfmem32_3);
    get_reg_off(pfmem32_4);
    get_reg_off(pfmem32_5);
    get_reg_off(pfmem32_6);
    get_reg_off(pfmem32_7);
    get_reg_off(pfmem32_8);
    get_reg_off(pfmem32_9);
    get_reg_off(pfmem32_10);
    get_reg_off(pfmem32_11);
    get_reg_off(pfmem32_12);
    get_reg_off(pfmem32_13);
    get_reg_off(pfmem32_14);
    get_reg_off(pfmem32_15);
    get_reg_off(pfmem32_16);
    get_reg_off(pfmem32_17);
    get_reg_off(pfmem32_18);
    get_reg_off(pfmem32_19);


    get_reg_off(pfmem64_0);
    get_reg_off(pfmem64_1);
    get_reg_off(pfmem64_2);
    get_reg_off(pfmem64_3);
    get_reg_off(pfmem64_4);
    get_reg_off(pfmem64_5);
    get_reg_off(pfmem64_6);
    get_reg_off(pfmem64_7);
    get_reg_off(pfmem64_8);
    get_reg_off(pfmem64_9);
    get_reg_off(pfmem64_10);
    get_reg_off(pfmem64_11);
    get_reg_off(pfmem64_12);
    get_reg_off(pfmem64_13);
    get_reg_off(pfmem64_14);
    get_reg_off(pfmem64_15);
    get_reg_off(pfmem64_16);
    get_reg_off(pfmem64_17);
    get_reg_off(pfmem64_18);
    get_reg_off(pfmem64_19);

    return dict;
}


static PyGetSetDef JitCpu_getseters[] = {
    {"cpu",
     (getter)JitCpu_get_cpu, (setter)JitCpu_set_cpu,
     "first name",
     NULL},

    {"R0" , (getter)JitCpu_get_R0 , (setter)JitCpu_set_R0 , "R0" , NULL},
    {"R1" , (getter)JitCpu_get_R1 , (setter)JitCpu_set_R1 , "R1" , NULL},
    {"R2" , (getter)JitCpu_get_R2 , (setter)JitCpu_set_R2 , "R2" , NULL},
    {"R3" , (getter)JitCpu_get_R3 , (setter)JitCpu_set_R3 , "R3" , NULL},
    {"R4" , (getter)JitCpu_get_R4 , (setter)JitCpu_set_R4 , "R4" , NULL},
    {"R5" , (getter)JitCpu_get_R5 , (setter)JitCpu_set_R5 , "R5" , NULL},
    {"R6" , (getter)JitCpu_get_R6 , (setter)JitCpu_set_R6 , "R6" , NULL},
    {"R7" , (getter)JitCpu_get_R7 , (setter)JitCpu_set_R7 , "R7" , NULL},
    {"R8" , (getter)JitCpu_get_R8 , (setter)JitCpu_set_R8 , "R8" , NULL},
    {"R9" , (getter)JitCpu_get_R9 , (setter)JitCpu_set_R9 , "R9" , NULL},
    {"R10", (getter)JitCpu_get_R10, (setter)JitCpu_set_R10, "R10", NULL},
    {"R11", (getter)JitCpu_get_R11, (setter)JitCpu_set_R11, "R11", NULL},
    {"R12", (getter)JitCpu_get_R12, (setter)JitCpu_set_R12, "R12", NULL},
    {"SP" , (getter)JitCpu_get_SP , (setter)JitCpu_set_SP , "SP" , NULL},
    {"LR" , (getter)JitCpu_get_LR , (setter)JitCpu_set_LR , "LR" , NULL},
    {"PC" , (getter)JitCpu_get_PC , (setter)JitCpu_set_PC , "PC" , NULL},

    {"zf", (getter)JitCpu_get_zf, (setter)JitCpu_set_zf, "zf", NULL},
    {"nf", (getter)JitCpu_get_nf, (setter)JitCpu_set_nf, "nf", NULL},
    {"of", (getter)JitCpu_get_of, (setter)JitCpu_set_of, "of", NULL},
    {"cf", (getter)JitCpu_get_cf, (setter)JitCpu_set_cf, "cf", NULL},

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "JitCore_arm.JitCpu",      /*tp_name*/
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



static PyMethodDef JitCore_arm_Methods[] = {

	/*

	*/
	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};

static PyObject *JitCore_arm_Error;

PyMODINIT_FUNC
initJitCore_arm(void)
{
    PyObject *m;

    if (PyType_Ready(&JitCpuType) < 0)
	return;

    m = Py_InitModule("JitCore_arm", JitCore_arm_Methods);
    if (m == NULL)
	    return;

    JitCore_arm_Error = PyErr_NewException("JitCore_arm.error", NULL, NULL);
    Py_INCREF(JitCore_arm_Error);
    PyModule_AddObject(m, "error", JitCore_arm_Error);

    Py_INCREF(&JitCpuType);
    PyModule_AddObject(m, "JitCpu", (PyObject *)&JitCpuType);

}

