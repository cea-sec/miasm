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
#include "JitCore_msp430.h"


reg_dict gpreg_dict[] = { {.name = "PC", .offset = offsetof(struct vm_cpu, PC)},
			  {.name = "SP", .offset = offsetof(struct vm_cpu, SP)},
			  //{.name = "SR", .offset = offsetof(struct vm_cpu, SR)},
			  {.name = "R3", .offset = offsetof(struct vm_cpu, R3)},
			  {.name = "R4", .offset = offsetof(struct vm_cpu, R4)},
			  {.name = "R5", .offset = offsetof(struct vm_cpu, R5)},
			  {.name = "R6", .offset = offsetof(struct vm_cpu, R6)},
			  {.name = "R7", .offset = offsetof(struct vm_cpu, R7)},
			  {.name = "R8", .offset = offsetof(struct vm_cpu, R8)},
			  {.name = "R9", .offset = offsetof(struct vm_cpu, R9)},
			  {.name = "R10", .offset = offsetof(struct vm_cpu, R10)},
			  {.name = "R11", .offset = offsetof(struct vm_cpu, R11)},
			  {.name = "R12", .offset = offsetof(struct vm_cpu, R12)},
			  {.name = "R13", .offset = offsetof(struct vm_cpu, R13)},
			  {.name = "R14", .offset = offsetof(struct vm_cpu, R14)},
			  {.name = "R15", .offset = offsetof(struct vm_cpu, R15)},

			  {.name = "zf", .offset = offsetof(struct vm_cpu, zf)},
			  {.name = "nf", .offset = offsetof(struct vm_cpu, nf)},
			  {.name = "of", .offset = offsetof(struct vm_cpu, of)},
			  {.name = "cf", .offset = offsetof(struct vm_cpu, cf)},

			  {.name = "cpuoff", .offset = offsetof(struct vm_cpu, cpuoff)},
			  {.name = "gie", .offset = offsetof(struct vm_cpu, gie)},
			  {.name = "osc", .offset = offsetof(struct vm_cpu, osc)},
			  {.name = "scg0", .offset = offsetof(struct vm_cpu, scg0)},
			  {.name = "scg1", .offset = offsetof(struct vm_cpu, scg1)},
			  {.name = "res", .offset = offsetof(struct vm_cpu, res)},

};

/************************** JitCpu object **************************/



PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(PC);
    get_reg(SP);
    //get_reg(SR);
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
    get_reg(R13);
    get_reg(R14);
    get_reg(R15);

    get_reg(zf);
    get_reg(nf);
    get_reg(of);
    get_reg(cf);

    get_reg(cpuoff);
    get_reg(gie);
    get_reg(osc);
    get_reg(scg0);
    get_reg(scg1);
    get_reg(res);


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

	printf("PC  %.4"PRIX32" SP  %.4"PRIX32"  R3  %.4"PRIX32" ",
	       vmcpu->PC, vmcpu->SP, vmcpu->R3);
	printf("R4  %.4"PRIX32" R5  %.4"PRIX32" R6  %.4"PRIX32" R7  %.4"PRIX32"\n",
	       vmcpu->R4, vmcpu->R5, vmcpu->R6, vmcpu->R7);
	printf("R8  %.4"PRIX32" R9  %.4"PRIX32" R10 %.4"PRIX32" R11 %.4"PRIX32" ",
	       vmcpu->R8, vmcpu->R9, vmcpu->R10, vmcpu->R11);
	printf("R12 %.4"PRIX32" R13 %.4"PRIX32" R14 %.4"PRIX32" R15 %.4"PRIX32"\n",
	       vmcpu->R12, vmcpu->R13, vmcpu->R14, vmcpu->R15);
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

getset_reg_u16(PC);
getset_reg_u16(SP);
getset_reg_u16(R3);
getset_reg_u16(R4);
getset_reg_u16(R5);
getset_reg_u16(R6);
getset_reg_u16(R7);
getset_reg_u16(R8);
getset_reg_u16(R9);
getset_reg_u16(R10);
getset_reg_u16(R11);
getset_reg_u16(R12);
getset_reg_u16(R13);
getset_reg_u16(R14);
getset_reg_u16(R15);
getset_reg_u16(zf);
getset_reg_u16(nf);
getset_reg_u16(of);
getset_reg_u16(cf);
getset_reg_u16(cpuoff);
getset_reg_u16(gie);
getset_reg_u16(osc);
getset_reg_u16(scg0);
getset_reg_u16(scg1);
getset_reg_u16(res);



PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;
    get_reg_off(exception_flags);

    get_reg_off(PC);
    get_reg_off(SP);
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
    get_reg_off(R13);
    get_reg_off(R14);
    get_reg_off(R15);

    get_reg_off(zf);
    get_reg_off(nf);
    get_reg_off(of);
    get_reg_off(cf);
    get_reg_off(cpuoff);
    get_reg_off(gie);
    get_reg_off(osc);
    get_reg_off(scg0);
    get_reg_off(scg1);
    get_reg_off(res);

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


    {"PC" , (getter)JitCpu_get_PC      , (setter)JitCpu_set_PC     , "PC" , NULL},
    {"SP" , (getter)JitCpu_get_SP      , (setter)JitCpu_set_SP     , "SP" , NULL},
    {"R3" , (getter)JitCpu_get_R3      , (setter)JitCpu_set_R3     , "R3" , NULL},
    {"R4" , (getter)JitCpu_get_R4      , (setter)JitCpu_set_R4     , "R4" , NULL},
    {"R5" , (getter)JitCpu_get_R5      , (setter)JitCpu_set_R5     , "R5" , NULL},
    {"R6" , (getter)JitCpu_get_R6      , (setter)JitCpu_set_R6     , "R6" , NULL},
    {"R7" , (getter)JitCpu_get_R7      , (setter)JitCpu_set_R7     , "R7" , NULL},
    {"R8" , (getter)JitCpu_get_R8      , (setter)JitCpu_set_R8     , "R8" , NULL},
    {"R9" , (getter)JitCpu_get_R9      , (setter)JitCpu_set_R9     , "R9" , NULL},
    {"R10" , (getter)JitCpu_get_R10    , (setter)JitCpu_set_R10    , "R10" , NULL},
    {"R11" , (getter)JitCpu_get_R11    , (setter)JitCpu_set_R11    , "R11" , NULL},
    {"R12" , (getter)JitCpu_get_R12    , (setter)JitCpu_set_R12    , "R12" , NULL},
    {"R13" , (getter)JitCpu_get_R13    , (setter)JitCpu_set_R13    , "R13" , NULL},
    {"R14" , (getter)JitCpu_get_R14    , (setter)JitCpu_set_R14    , "R14" , NULL},
    {"R15" , (getter)JitCpu_get_R15    , (setter)JitCpu_set_R15    , "R15" , NULL},
    {"zf" , (getter)JitCpu_get_zf      , (setter)JitCpu_set_zf     , "zf" , NULL},
    {"nf" , (getter)JitCpu_get_nf      , (setter)JitCpu_set_nf     , "nf" , NULL},
    {"of" , (getter)JitCpu_get_of      , (setter)JitCpu_set_of     , "of" , NULL},
    {"cf" , (getter)JitCpu_get_cf      , (setter)JitCpu_set_cf     , "cf" , NULL},
    {"cpuoff" , (getter)JitCpu_get_cpuoff , (setter)JitCpu_set_cpuoff , "cpuoff" , NULL},
    {"gie" , (getter)JitCpu_get_gie    , (setter)JitCpu_set_gie    , "gie" , NULL},
    {"osc" , (getter)JitCpu_get_osc    , (setter)JitCpu_set_osc    , "osc" , NULL},
    {"scg0" , (getter)JitCpu_get_scg0   , (setter)JitCpu_set_scg0   , "scg0" , NULL},
    {"scg1" , (getter)JitCpu_get_scg1   , (setter)JitCpu_set_scg1   , "scg1" , NULL},
    {"res" , (getter)JitCpu_get_res    , (setter)JitCpu_set_res    , "res" , NULL},

    {NULL}  /* Sentinel */
};



static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "JitCore_msp430.JitCpu",   /*tp_name*/
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



static PyMethodDef JitCore_msp430_Methods[] = {

	/*

	*/
	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};




MOD_INIT(JitCore_msp430)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_msp430", "JitCore_msp430 module", JitCore_msp430_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}
