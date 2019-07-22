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
#include "JitCore_aarch64.h"



reg_dict gpreg_dict[] = {
	{.name = "X0", .offset = offsetof(struct vm_cpu, X0), .size = 64},
	{.name = "X1", .offset = offsetof(struct vm_cpu, X1), .size = 64},
	{.name = "X2", .offset = offsetof(struct vm_cpu, X2), .size = 64},
	{.name = "X3", .offset = offsetof(struct vm_cpu, X3), .size = 64},
	{.name = "X4", .offset = offsetof(struct vm_cpu, X4), .size = 64},
	{.name = "X5", .offset = offsetof(struct vm_cpu, X5), .size = 64},
	{.name = "X6", .offset = offsetof(struct vm_cpu, X6), .size = 64},
	{.name = "X7", .offset = offsetof(struct vm_cpu, X7), .size = 64},
	{.name = "X8", .offset = offsetof(struct vm_cpu, X8), .size = 64},
	{.name = "X9", .offset = offsetof(struct vm_cpu, X9), .size = 64},
	{.name = "X10", .offset = offsetof(struct vm_cpu, X10), .size = 64},
	{.name = "X11", .offset = offsetof(struct vm_cpu, X11), .size = 64},
	{.name = "X12", .offset = offsetof(struct vm_cpu, X12), .size = 64},
	{.name = "X13", .offset = offsetof(struct vm_cpu, X13), .size = 64},
	{.name = "X14", .offset = offsetof(struct vm_cpu, X14), .size = 64},
	{.name = "X15", .offset = offsetof(struct vm_cpu, X15), .size = 64},
	{.name = "X16", .offset = offsetof(struct vm_cpu, X16), .size = 64},
	{.name = "X17", .offset = offsetof(struct vm_cpu, X17), .size = 64},
	{.name = "X18", .offset = offsetof(struct vm_cpu, X18), .size = 64},
	{.name = "X19", .offset = offsetof(struct vm_cpu, X19), .size = 64},
	{.name = "X20", .offset = offsetof(struct vm_cpu, X20), .size = 64},
	{.name = "X21", .offset = offsetof(struct vm_cpu, X21), .size = 64},
	{.name = "X22", .offset = offsetof(struct vm_cpu, X22), .size = 64},
	{.name = "X23", .offset = offsetof(struct vm_cpu, X23), .size = 64},
	{.name = "X24", .offset = offsetof(struct vm_cpu, X24), .size = 64},
	{.name = "X25", .offset = offsetof(struct vm_cpu, X25), .size = 64},
	{.name = "X26", .offset = offsetof(struct vm_cpu, X26), .size = 64},
	{.name = "X27", .offset = offsetof(struct vm_cpu, X27), .size = 64},
	{.name = "X28", .offset = offsetof(struct vm_cpu, X28), .size = 64},
	{.name = "X29", .offset = offsetof(struct vm_cpu, X29), .size = 64},
	{.name = "LR", .offset = offsetof(struct vm_cpu, LR), .size = 64},

	{.name = "SP", .offset = offsetof(struct vm_cpu, SP), .size = 64},
	{.name = "PC", .offset = offsetof(struct vm_cpu, PC), .size = 64},

	{.name = "zf", .offset = offsetof(struct vm_cpu, zf), .size = 8},
	{.name = "nf", .offset = offsetof(struct vm_cpu, nf), .size = 8},
	{.name = "of", .offset = offsetof(struct vm_cpu, of), .size = 8},
	{.name = "cf", .offset = offsetof(struct vm_cpu, cf), .size = 8},

	{.name = "exception_flags", .offset = offsetof(struct vm_cpu, exception_flags), .size = 32},
	{.name = "interrupt_num", .offset = offsetof(struct vm_cpu, interrupt_num), .size = 32},

};

/************************** JitCpu object **************************/




PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(X0);
    get_reg(X1);
    get_reg(X2);
    get_reg(X3);
    get_reg(X4);
    get_reg(X5);
    get_reg(X6);
    get_reg(X7);
    get_reg(X8);
    get_reg(X9);
    get_reg(X10);
    get_reg(X11);
    get_reg(X12);
    get_reg(X13);
    get_reg(X14);
    get_reg(X15);
    get_reg(X16);
    get_reg(X17);
    get_reg(X18);
    get_reg(X19);
    get_reg(X20);
    get_reg(X21);
    get_reg(X22);
    get_reg(X23);
    get_reg(X24);
    get_reg(X25);
    get_reg(X26);
    get_reg(X27);
    get_reg(X28);
    get_reg(X29);
    get_reg(LR);
    get_reg(SP);
    get_reg(PC);

    get_reg(zf);
    get_reg(nf);
    get_reg(of);
    get_reg(cf);

    return dict;
}



PyObject* cpu_set_gpreg(JitCpu* self, PyObject *args)
{
    PyObject* dict;
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    const char *d_key_name;
    uint32_t val32;
    uint64_t val64;
    unsigned int i, found;

    if (!PyArg_ParseTuple(args, "O", &dict))
	    RAISE(PyExc_TypeError,"Cannot parse arguments");
    if(!PyDict_Check(dict))
	    RAISE(PyExc_TypeError, "arg must be dict");
    while(PyDict_Next(dict, &pos, &d_key, &d_value)){
	    PyGetStr(d_key_name, d_key);
	    found = 0;
	    for (i=0; i < sizeof(gpreg_dict)/sizeof(reg_dict); i++){
		    if (strcmp(d_key_name, gpreg_dict[i].name))
			    continue;
		    found = 1;
		    switch (gpreg_dict[i].size) {
			    default:
				    RAISE(PyExc_TypeError, "Unsupported size");
				    break;
			    case 32:
				    PyGetInt_uint32_t(d_value, val32);
				    *((uint32_t*)(((char*)(self->cpu)) + gpreg_dict[i].offset)) = val32;
				    break;
			    case 64:
				    PyGetInt_uint64_t(d_value, val64);
				    *((uint64_t*)(((char*)(self->cpu)) + gpreg_dict[i].offset)) = val64;
				    break;
		    }
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
	printf("X0  %.16"PRIX64" X1  %.16"PRIX64" X2  %.16"PRIX64" X3  %.16"PRIX64" "\
	       "X4  %.16"PRIX64" X5  %.16"PRIX64" X6  %.16"PRIX64" X7  %.16"PRIX64"\n",
	       vmcpu->X0, vmcpu->X1, vmcpu->X2, vmcpu->X3, vmcpu->X4, vmcpu->X5, vmcpu->X6, vmcpu->X7);
	printf("X8  %.16"PRIX64" X9  %.16"PRIX64" X10 %.16"PRIX64" X11 %.16"PRIX64" "\
	       "X12 %.16"PRIX64" X13 %.16"PRIX64" X14 %.16"PRIX64" X15 %.16"PRIX64"\n",
	       vmcpu->X8, vmcpu->X9, vmcpu->X10, vmcpu->X11,
	       vmcpu->X12, vmcpu->X13, vmcpu->X14, vmcpu->X15);
	printf("X16 %.16"PRIX64" X17 %.16"PRIX64" X18 %.16"PRIX64" X19 %.16"PRIX64" "\
	       "X20 %.16"PRIX64" X21 %.16"PRIX64" X22 %.16"PRIX64" X23 %.16"PRIX64"\n",
	       vmcpu->X16, vmcpu->X17, vmcpu->X18, vmcpu->X19,
	       vmcpu->X20, vmcpu->X21, vmcpu->X22, vmcpu->X23);
	printf("X24 %.16"PRIX64" X25 %.16"PRIX64" X26 %.16"PRIX64" X27 %.16"PRIX64" "\
	       "X28 %.16"PRIX64" X29 %.16"PRIX64" LR  %.16"PRIX64"\n",
	       vmcpu->X24, vmcpu->X25, vmcpu->X26, vmcpu->X27,
	       vmcpu->X28, vmcpu->X29, vmcpu->LR);


	printf("SP  %.16"PRIX64" PC  %.16"PRIX64" "\
	       "zf  %"PRIX32" nf  %"PRIX32" of  %"PRIX32" cf  %"PRIX32"\n",
	       vmcpu->SP, vmcpu->PC,
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



getset_reg_u64(X0);
getset_reg_u64(X1);
getset_reg_u64(X2);
getset_reg_u64(X3);
getset_reg_u64(X4);
getset_reg_u64(X5);
getset_reg_u64(X6);
getset_reg_u64(X7);
getset_reg_u64(X8);
getset_reg_u64(X9);
getset_reg_u64(X10);
getset_reg_u64(X11);
getset_reg_u64(X12);
getset_reg_u64(X13);
getset_reg_u64(X14);
getset_reg_u64(X15);
getset_reg_u64(X16);
getset_reg_u64(X17);
getset_reg_u64(X18);
getset_reg_u64(X19);
getset_reg_u64(X20);
getset_reg_u64(X21);
getset_reg_u64(X22);
getset_reg_u64(X23);
getset_reg_u64(X24);
getset_reg_u64(X25);
getset_reg_u64(X26);
getset_reg_u64(X27);
getset_reg_u64(X28);
getset_reg_u64(X29);
getset_reg_u64(LR);
getset_reg_u64(SP);
getset_reg_u64(PC);

getset_reg_u32(zf);
getset_reg_u32(nf);
getset_reg_u32(of);
getset_reg_u32(cf);


getset_reg_u32(exception_flags);
getset_reg_u32(interrupt_num);


PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg_off(exception_flags);

    get_reg_off(X0);
    get_reg_off(X1);
    get_reg_off(X2);
    get_reg_off(X3);
    get_reg_off(X4);
    get_reg_off(X5);
    get_reg_off(X6);
    get_reg_off(X7);
    get_reg_off(X8);
    get_reg_off(X9);
    get_reg_off(X10);
    get_reg_off(X11);
    get_reg_off(X12);
    get_reg_off(X13);
    get_reg_off(X14);
    get_reg_off(X15);
    get_reg_off(X16);
    get_reg_off(X17);
    get_reg_off(X18);
    get_reg_off(X19);
    get_reg_off(X20);
    get_reg_off(X21);
    get_reg_off(X22);
    get_reg_off(X23);
    get_reg_off(X24);
    get_reg_off(X25);
    get_reg_off(X26);
    get_reg_off(X27);
    get_reg_off(X28);
    get_reg_off(X29);
    get_reg_off(LR);
    get_reg_off(SP);
    get_reg_off(PC);

    /* eflag */
    get_reg_off(zf);
    get_reg_off(nf);
    get_reg_off(of);
    get_reg_off(cf);

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



    {"X0" , (getter)JitCpu_get_X0 , (setter)JitCpu_set_X0 , "X0" , NULL},
    {"X1" , (getter)JitCpu_get_X1 , (setter)JitCpu_set_X1 , "X1" , NULL},
    {"X2" , (getter)JitCpu_get_X2 , (setter)JitCpu_set_X2 , "X2" , NULL},
    {"X3" , (getter)JitCpu_get_X3 , (setter)JitCpu_set_X3 , "X3" , NULL},
    {"X4" , (getter)JitCpu_get_X4 , (setter)JitCpu_set_X4 , "X4" , NULL},
    {"X5" , (getter)JitCpu_get_X5 , (setter)JitCpu_set_X5 , "X5" , NULL},
    {"X6" , (getter)JitCpu_get_X6 , (setter)JitCpu_set_X6 , "X6" , NULL},
    {"X7" , (getter)JitCpu_get_X7 , (setter)JitCpu_set_X7 , "X7" , NULL},
    {"X8" , (getter)JitCpu_get_X8 , (setter)JitCpu_set_X8 , "X8" , NULL},
    {"X9" , (getter)JitCpu_get_X9 , (setter)JitCpu_set_X9 , "X9" , NULL},

    {"X10" , (getter)JitCpu_get_X10 , (setter)JitCpu_set_X10 , "X10" , NULL},
    {"X11" , (getter)JitCpu_get_X11 , (setter)JitCpu_set_X11 , "X11" , NULL},
    {"X12" , (getter)JitCpu_get_X12 , (setter)JitCpu_set_X12 , "X12" , NULL},
    {"X13" , (getter)JitCpu_get_X13 , (setter)JitCpu_set_X13 , "X13" , NULL},
    {"X14" , (getter)JitCpu_get_X14 , (setter)JitCpu_set_X14 , "X14" , NULL},
    {"X15" , (getter)JitCpu_get_X15 , (setter)JitCpu_set_X15 , "X15" , NULL},
    {"X16" , (getter)JitCpu_get_X16 , (setter)JitCpu_set_X16 , "X16" , NULL},
    {"X17" , (getter)JitCpu_get_X17 , (setter)JitCpu_set_X17 , "X17" , NULL},
    {"X18" , (getter)JitCpu_get_X18 , (setter)JitCpu_set_X18 , "X18" , NULL},
    {"X19" , (getter)JitCpu_get_X19 , (setter)JitCpu_set_X19 , "X19" , NULL},

    {"X20" , (getter)JitCpu_get_X20 , (setter)JitCpu_set_X20 , "X20" , NULL},
    {"X21" , (getter)JitCpu_get_X21 , (setter)JitCpu_set_X21 , "X21" , NULL},
    {"X22" , (getter)JitCpu_get_X22 , (setter)JitCpu_set_X22 , "X22" , NULL},
    {"X23" , (getter)JitCpu_get_X23 , (setter)JitCpu_set_X23 , "X23" , NULL},
    {"X24" , (getter)JitCpu_get_X24 , (setter)JitCpu_set_X24 , "X24" , NULL},
    {"X25" , (getter)JitCpu_get_X25 , (setter)JitCpu_set_X25 , "X25" , NULL},
    {"X26" , (getter)JitCpu_get_X26 , (setter)JitCpu_set_X26 , "X26" , NULL},
    {"X27" , (getter)JitCpu_get_X27 , (setter)JitCpu_set_X27 , "X27" , NULL},
    {"X28" , (getter)JitCpu_get_X28 , (setter)JitCpu_set_X28 , "X28" , NULL},
    {"X29" , (getter)JitCpu_get_X29 , (setter)JitCpu_set_X29 , "X29" , NULL},

    {"LR" , (getter)JitCpu_get_LR , (setter)JitCpu_set_LR , "LR" , NULL},



    {"SP" , (getter)JitCpu_get_SP , (setter)JitCpu_set_SP , "SP" , NULL},
    {"PC" , (getter)JitCpu_get_PC , (setter)JitCpu_set_PC , "PC" , NULL},

    {"zf", (getter)JitCpu_get_zf, (setter)JitCpu_set_zf, "zf", NULL},
    {"nf", (getter)JitCpu_get_nf, (setter)JitCpu_set_nf, "nf", NULL},
    {"of", (getter)JitCpu_get_of, (setter)JitCpu_set_of, "of", NULL},
    {"cf", (getter)JitCpu_get_cf, (setter)JitCpu_set_cf, "cf", NULL},

    {"exception_flags", (getter)JitCpu_get_exception_flags, (setter)JitCpu_set_exception_flags, "exception_flags", NULL},
    {"interrupt_num", (getter)JitCpu_get_interrupt_num, (setter)JitCpu_set_interrupt_num, "interrupt_num", NULL},

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "JitCore_aarch64.JitCpu",  /*tp_name*/
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



static PyMethodDef JitCore_aarch64_Methods[] = {
	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};



MOD_INIT(JitCore_aarch64)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_aarch64", "JitCore_aarch64 module", JitCore_aarch64_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}

