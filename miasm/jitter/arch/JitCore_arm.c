#include <Python.h>
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include "../compat_py23.h"
#include "../queue.h"
#include "../vm_mngr.h"
#include "../bn.h"
#include "../vm_mngr_py.h"
#include "../JitCore.h"
#include "../op_semantics.h"
#include "JitCore_arm.h"



reg_dict gpreg_dict[] = {
			 {.name = "R0", .offset = offsetof(struct vm_cpu, R0), .size = 32},
			 {.name = "R1", .offset = offsetof(struct vm_cpu, R1), .size = 32},
			 {.name = "R2", .offset = offsetof(struct vm_cpu, R2), .size = 32},
			 {.name = "R3", .offset = offsetof(struct vm_cpu, R3), .size = 32},
			 {.name = "R4", .offset = offsetof(struct vm_cpu, R4), .size = 32},
			 {.name = "R5", .offset = offsetof(struct vm_cpu, R5), .size = 32},
			 {.name = "R6", .offset = offsetof(struct vm_cpu, R6), .size = 32},
			 {.name = "R7", .offset = offsetof(struct vm_cpu, R7), .size = 32},
			 {.name = "R8", .offset = offsetof(struct vm_cpu, R8), .size = 32},
			 {.name = "R9", .offset = offsetof(struct vm_cpu, R9), .size = 32},
			 {.name = "R10", .offset = offsetof(struct vm_cpu, R10), .size = 32},
			 {.name = "R11", .offset = offsetof(struct vm_cpu, R11), .size = 32},
			 {.name = "R12", .offset = offsetof(struct vm_cpu, R12), .size = 32},
			 {.name = "SP", .offset = offsetof(struct vm_cpu, SP), .size = 32},
			 {.name = "LR", .offset = offsetof(struct vm_cpu, LR), .size = 32},
			 {.name = "PC", .offset = offsetof(struct vm_cpu, PC), .size = 32},

			 {.name = "zf", .offset = offsetof(struct vm_cpu, zf), .size = 8},
			 {.name = "nf", .offset = offsetof(struct vm_cpu, nf), .size = 8},
			 {.name = "of", .offset = offsetof(struct vm_cpu, of), .size = 8},
			 {.name = "cf", .offset = offsetof(struct vm_cpu, cf), .size = 8},

			 {.name = "ge0", .offset = offsetof(struct vm_cpu, ge0), .size = 8},
			 {.name = "ge1", .offset = offsetof(struct vm_cpu, ge1), .size = 8},
			 {.name = "ge2", .offset = offsetof(struct vm_cpu, ge2), .size = 8},
			 {.name = "ge3", .offset = offsetof(struct vm_cpu, ge3), .size = 8},

			 {.name = "exception_flags", .offset = offsetof(struct vm_cpu, exception_flags), .size = 32},
			 {.name = "interrupt_num", .offset = offsetof(struct vm_cpu, interrupt_num), .size = 32},
};

/************************** JitCpu object **************************/




PyObject* cpu_get_gpreg(JitCpu* self)
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

    get_reg(ge0);
    get_reg(ge1);
    get_reg(ge2);
    get_reg(ge3);

    return dict;
}



PyObject* cpu_set_gpreg(JitCpu* self, PyObject *args)
{
    PyObject* dict;
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    const char *d_key_name;
    uint32_t val;
    unsigned int i, found;

    if (!PyArg_ParseTuple(args, "O", &dict))
	    RAISE(PyExc_TypeError,"Cannot parse arguments");
    if(!PyDict_Check(dict))
	    RAISE(PyExc_TypeError, "arg must be dict");
    while(PyDict_Next(dict, &pos, &d_key, &d_value)){
	    PyGetStr(d_key_name, d_key);
	    PyGetInt_uint32_t(d_value, val);

	    found = 0;
	    for (i=0; i < sizeof(gpreg_dict)/sizeof(reg_dict); i++){
		    if (strcmp(d_key_name, gpreg_dict[i].name))
			    continue;
		    *((uint32_t*)(((char*)(self->cpu)) + gpreg_dict[i].offset)) = val;
		    found = 1;
		    break;
	    }

	    if (found)
		    continue;
	    fprintf(stderr, "unknown key: %s\n", d_key_name);
	    RAISE(PyExc_ValueError, "unknown reg");
    }
    Py_INCREF(Py_None);
    return Py_None;
}


PyObject * cpu_init_regs(JitCpu* self)
{
	memset(self->cpu, 0, sizeof(struct vm_cpu));

	Py_INCREF(Py_None);
	return Py_None;
}

void dump_gpregs(struct vm_cpu* vmcpu)
{
	printf("R0  %.8"PRIX32" R1  %.8"PRIX32" R2  %.8"PRIX32" R3  %.8"PRIX32" ",
	       vmcpu->R0, vmcpu->R1, vmcpu->R2, vmcpu->R3);
	printf("R4  %.8"PRIX32" R5  %.8"PRIX32" R6  %.8"PRIX32" R7  %.8"PRIX32"\n",
	       vmcpu->R4, vmcpu->R5, vmcpu->R6, vmcpu->R7);
	printf("R8  %.8"PRIX32" R9  %.8"PRIX32" R10 %.8"PRIX32" R11 %.8"PRIX32" ",
	       vmcpu->R8, vmcpu->R9, vmcpu->R10, vmcpu->R11);
	printf("R12 %.8"PRIX32" SP  %.8"PRIX32" LR  %.8"PRIX32" PC  %.8"PRIX32" ",
	       vmcpu->R12, vmcpu->SP, vmcpu->LR, vmcpu->PC);
	printf("zf %"PRIX32" nf %"PRIX32" of %"PRIX32" cf %"PRIX32"\n",
	       vmcpu->zf, vmcpu->nf, vmcpu->of, vmcpu->cf);
}


PyObject * cpu_dump_gpregs(JitCpu* self, PyObject* args)
{
	struct vm_cpu* vmcpu;

	vmcpu = self->cpu;
	dump_gpregs(vmcpu);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject * cpu_dump_gpregs_with_attrib(JitCpu* self, PyObject* args)
{
	return cpu_dump_gpregs(self, args);
}



PyObject* cpu_set_exception(JitCpu* self, PyObject* args)
{
	PyObject *item1;
	uint32_t exception_flags;

	if (!PyArg_ParseTuple(args, "O", &item1))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint32_t(item1, exception_flags);

	((struct vm_cpu*)self->cpu)->exception_flags = exception_flags;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* cpu_get_exception(JitCpu* self, PyObject* args)
{
	return PyLong_FromUnsignedLongLong((uint64_t)(((struct vm_cpu*)self->cpu)->exception_flags));
}

void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src)
{
	vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src)
{
	vm_MEM_WRITE_16(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src)
{
	vm_MEM_WRITE_32(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src)
{
	vm_MEM_WRITE_64(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

PyObject* cpu_set_interrupt_num(JitCpu* self, PyObject* args)
{
	PyObject *item1;
	uint32_t exception_flags;

	if (!PyArg_ParseTuple(args, "O", &item1))
		RAISE(PyExc_TypeError,"Cannot parse arguments");

	PyGetInt_uint32_t(item1, exception_flags);

	((struct vm_cpu*)self->cpu)->interrupt_num = exception_flags;
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject* cpu_get_interrupt_num(JitCpu* self, PyObject* args)
{
	return PyLong_FromUnsignedLongLong((uint64_t)(((struct vm_cpu*)self->cpu)->interrupt_num));
}

static PyMemberDef JitCpu_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef JitCpu_methods[] = {
	{"init_regs", (PyCFunction)cpu_init_regs, METH_NOARGS,
	 "X"},
	{"dump_gpregs", (PyCFunction)cpu_dump_gpregs, METH_NOARGS,
	 "X"},
	{"dump_gpregs_with_attrib", (PyCFunction)cpu_dump_gpregs_with_attrib, METH_VARARGS,
	 "X"},
	{"get_gpreg", (PyCFunction)cpu_get_gpreg, METH_NOARGS,
	 "X"},
	{"set_gpreg", (PyCFunction)cpu_set_gpreg, METH_VARARGS,
	 "X"},
	{"get_exception", (PyCFunction)cpu_get_exception, METH_VARARGS,
	 "X"},
	{"set_exception", (PyCFunction)cpu_set_exception, METH_VARARGS,
	 "X"},
	{"get_interrupt_num", (PyCFunction)cpu_get_interrupt_num, METH_VARARGS,
	 "X"},
	{"set_interrupt_num", (PyCFunction)cpu_set_interrupt_num, METH_VARARGS,
	 "X"},
	{NULL}  /* Sentinel */
};

static int
JitCpu_init(JitCpu *self, PyObject *args, PyObject *kwds)
{
	self->cpu = malloc(sizeof(struct vm_cpu));
	if (self->cpu == NULL) {
		fprintf(stderr, "cannot alloc struct vm_cpu\n");
		exit(EXIT_FAILURE);
	}
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

getset_reg_u32(ge0);
getset_reg_u32(ge1);
getset_reg_u32(ge2);
getset_reg_u32(ge3);

getset_reg_u32(exception_flags);
getset_reg_u32(interrupt_num);

PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg_off(exception_flags);
    get_reg_off(interrupt_num);

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

	/* eflag */
    get_reg_off(zf);
    get_reg_off(nf);
    get_reg_off(of);
    get_reg_off(cf);

    get_reg_off(ge0);
    get_reg_off(ge1);
    get_reg_off(ge2);
    get_reg_off(ge3);

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

    {"ge0", (getter)JitCpu_get_ge0, (setter)JitCpu_set_ge0, "ge0", NULL},
    {"ge1", (getter)JitCpu_get_ge1, (setter)JitCpu_set_ge1, "ge1", NULL},
    {"ge2", (getter)JitCpu_get_ge2, (setter)JitCpu_set_ge2, "ge2", NULL},
    {"ge3", (getter)JitCpu_get_ge3, (setter)JitCpu_set_ge3, "ge3", NULL},

    {"exception_flags", (getter)JitCpu_get_exception_flags, (setter)JitCpu_set_exception_flags, "exception_flags", NULL},
    {"interrupt_num", (getter)JitCpu_get_interrupt_num, (setter)JitCpu_set_interrupt_num, "interrupt_num", NULL},

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
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



MOD_INIT(JitCore_arm)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_arm", "JitCore_arm module", JitCore_arm_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}

