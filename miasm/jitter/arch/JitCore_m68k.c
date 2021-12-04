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
#include "JitCore_m68k.h"



reg_dict gpreg_dict[] = {
			 {.name = "A0", .offset = offsetof(struct vm_cpu, A0), .size = 32},
			 {.name = "A1", .offset = offsetof(struct vm_cpu, A1), .size = 32},
			 {.name = "A2", .offset = offsetof(struct vm_cpu, A2), .size = 32},
			 {.name = "A3", .offset = offsetof(struct vm_cpu, A3), .size = 32},
			 {.name = "A4", .offset = offsetof(struct vm_cpu, A4), .size = 32},
			 {.name = "A5", .offset = offsetof(struct vm_cpu, A5), .size = 32},
			 {.name = "A6", .offset = offsetof(struct vm_cpu, A6), .size = 32},
			 {.name = "SP", .offset = offsetof(struct vm_cpu, SP), .size = 32},

			 {.name = "D0", .offset = offsetof(struct vm_cpu, D0), .size = 32},
			 {.name = "D1", .offset = offsetof(struct vm_cpu, D1), .size = 32},
			 {.name = "D2", .offset = offsetof(struct vm_cpu, D2), .size = 32},
			 {.name = "D3", .offset = offsetof(struct vm_cpu, D3), .size = 32},
			 {.name = "D4", .offset = offsetof(struct vm_cpu, D4), .size = 32},
			 {.name = "D5", .offset = offsetof(struct vm_cpu, D5), .size = 32},
			 {.name = "D6", .offset = offsetof(struct vm_cpu, D6), .size = 32},
			 {.name = "D7", .offset = offsetof(struct vm_cpu, D7), .size = 32},

			 {.name = "PC", .offset = offsetof(struct vm_cpu, PC), .size = 32},

			 {.name = "zf", .offset = offsetof(struct vm_cpu, zf), .size = 8},
			 {.name = "nf", .offset = offsetof(struct vm_cpu, nf), .size = 8},
			 {.name = "vf", .offset = offsetof(struct vm_cpu, vf), .size = 8},
			 {.name = "cf", .offset = offsetof(struct vm_cpu, cf), .size = 8},
			 {.name = "xf", .offset = offsetof(struct vm_cpu, xf), .size = 8},

			 {.name = "exception_flags", .offset = offsetof(struct vm_cpu, exception_flags), .size = 32},
			 {.name = "interrupt_num", .offset = offsetof(struct vm_cpu, interrupt_num), .size = 32},
};

/************************** JitCpu object **************************/




PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(A0);
    get_reg(A1);
    get_reg(A2);
    get_reg(A3);
    get_reg(A4);
    get_reg(A5);
    get_reg(A6);
    get_reg(SP);

    get_reg(D0);
    get_reg(D1);
    get_reg(D2);
    get_reg(D3);
    get_reg(D4);
    get_reg(D5);
    get_reg(D6);
    get_reg(D7);

    get_reg(PC);

    get_reg(zf);
    get_reg(nf);
    get_reg(vf);
    get_reg(cf);
    get_reg(xf);

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


uint64_t segm2addr(JitCpu* jitcpu, uint64_t segm, uint64_t addr)
{
	return addr;
}

void dump_gpregs(struct vm_cpu* vmcpu)
{
	printf("A0  %.8"PRIX32" A1  %.8"PRIX32" A2  %.8"PRIX32" A3  %.8"PRIX32" ",
	       vmcpu->A0, vmcpu->A1, vmcpu->A2, vmcpu->A3);
	printf("R4  %.8"PRIX32" A5  %.8"PRIX32" A6  %.8"PRIX32" SP  %.8"PRIX32"\n",
	       vmcpu->A4, vmcpu->A5, vmcpu->A6, vmcpu->SP);

	printf("D0  %.8"PRIX32" D1  %.8"PRIX32" D2  %.8"PRIX32" D3  %.8"PRIX32" ",
	       vmcpu->D0, vmcpu->D1, vmcpu->D2, vmcpu->D3);
	printf("R4  %.8"PRIX32" D5  %.8"PRIX32" D6  %.8"PRIX32" D7  %.8"PRIX32"\n",
	       vmcpu->D4, vmcpu->D5, vmcpu->D6, vmcpu->D7);


	printf("PC  %.8"PRIX32" ",
	       vmcpu->PC);
	printf("zf %"PRIX32" nf %"PRIX32" vf %"PRIX32"  cf %"PRIX32" xf %"PRIX32"\n",
	       vmcpu->zf, vmcpu->nf, vmcpu->vf, vmcpu->cf, vmcpu->xf);
}

void dump_gpregs_32(struct vm_cpu* vmcpu)
{
	dump_gpregs(vmcpu);
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

getset_reg_u32(A0);
getset_reg_u32(A1);
getset_reg_u32(A2);
getset_reg_u32(A3);
getset_reg_u32(A4);
getset_reg_u32(A5);
getset_reg_u32(A6);
getset_reg_u32(SP);

getset_reg_u32(D0);
getset_reg_u32(D1);
getset_reg_u32(D2);
getset_reg_u32(D3);
getset_reg_u32(D4);
getset_reg_u32(D5);
getset_reg_u32(D6);
getset_reg_u32(D7);
getset_reg_u32(PC);

getset_reg_u32(zf);
getset_reg_u32(nf);
getset_reg_u32(vf);
getset_reg_u32(cf);
getset_reg_u32(xf);

getset_reg_u32(exception_flags);
getset_reg_u32(interrupt_num);

PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg_off(exception_flags);
    get_reg_off(interrupt_num);

    get_reg_off(A0);
    get_reg_off(A1);
    get_reg_off(A2);
    get_reg_off(A3);
    get_reg_off(A4);
    get_reg_off(A5);
    get_reg_off(A6);
    get_reg_off(SP);

    get_reg_off(D0);
    get_reg_off(D1);
    get_reg_off(D2);
    get_reg_off(D3);
    get_reg_off(D4);
    get_reg_off(D5);
    get_reg_off(D6);
    get_reg_off(D7);

    get_reg_off(PC);

	/* eflag */
    get_reg_off(zf);
    get_reg_off(nf);
    get_reg_off(vf);
    get_reg_off(cf);
    get_reg_off(xf);

    return dict;
}

static PyGetSetDef JitCpu_getseters[] = {
    {"vmmngr",
     (getter)JitCpu_get_vmmngr, (setter)JitCpu_set_vmmngr,
     "vmmngr",
     NULL},

    {"vmcpu",
     (getter)JitCpu_get_vmcpu, (setter)JitCpu_set_vmcpu,
     "vmcpu",
     NULL},

    {"jitter",
     (getter)JitCpu_get_jitter, (setter)JitCpu_set_jitter,
     "jitter",
     NULL},



    {"A0" , (getter)JitCpu_get_A0 , (setter)JitCpu_set_A0 , "A0" , NULL},
    {"A1" , (getter)JitCpu_get_A1 , (setter)JitCpu_set_A1 , "A1" , NULL},
    {"A2" , (getter)JitCpu_get_A2 , (setter)JitCpu_set_A2 , "A2" , NULL},
    {"A3" , (getter)JitCpu_get_A3 , (setter)JitCpu_set_A3 , "A3" , NULL},
    {"A4" , (getter)JitCpu_get_A4 , (setter)JitCpu_set_A4 , "A4" , NULL},
    {"A5" , (getter)JitCpu_get_A5 , (setter)JitCpu_set_A5 , "A5" , NULL},
    {"A6" , (getter)JitCpu_get_A6 , (setter)JitCpu_set_A6 , "A6" , NULL},
    {"SP" , (getter)JitCpu_get_SP , (setter)JitCpu_set_SP , "SP" , NULL},

    {"D0" , (getter)JitCpu_get_D0 , (setter)JitCpu_set_D0 , "D0" , NULL},
    {"D1" , (getter)JitCpu_get_D1 , (setter)JitCpu_set_D1 , "D1" , NULL},
    {"D2" , (getter)JitCpu_get_D2 , (setter)JitCpu_set_D2 , "D2" , NULL},
    {"D3" , (getter)JitCpu_get_D3 , (setter)JitCpu_set_D3 , "D3" , NULL},
    {"D4" , (getter)JitCpu_get_D4 , (setter)JitCpu_set_D4 , "D4" , NULL},
    {"D5" , (getter)JitCpu_get_D5 , (setter)JitCpu_set_D5 , "D5" , NULL},
    {"D6" , (getter)JitCpu_get_D6 , (setter)JitCpu_set_D6 , "D6" , NULL},
    {"D7" , (getter)JitCpu_get_D7 , (setter)JitCpu_set_D7 , "D7" , NULL},

    {"PC" , (getter)JitCpu_get_PC , (setter)JitCpu_set_PC , "PC" , NULL},

    {"zf", (getter)JitCpu_get_zf, (setter)JitCpu_set_zf, "zf", NULL},
    {"nf", (getter)JitCpu_get_nf, (setter)JitCpu_set_nf, "nf", NULL},
    {"vf", (getter)JitCpu_get_vf, (setter)JitCpu_set_vf, "vf", NULL},
    {"cf", (getter)JitCpu_get_cf, (setter)JitCpu_set_cf, "cf", NULL},
    {"xf", (getter)JitCpu_get_xf, (setter)JitCpu_set_xf, "xf", NULL},

    {"exception_flags", (getter)JitCpu_get_exception_flags, (setter)JitCpu_set_exception_flags, "exception_flags", NULL},
    {"interrupt_num", (getter)JitCpu_get_interrupt_num, (setter)JitCpu_set_interrupt_num, "interrupt_num", NULL},

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "JitCore_m68k.JitCpu",      /*tp_name*/
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



static PyMethodDef JitCore_m68k_Methods[] = {

	/*

	*/
	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};



MOD_INIT(JitCore_m68k)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_m68k", "JitCore_m68k module", JitCore_m68k_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}

