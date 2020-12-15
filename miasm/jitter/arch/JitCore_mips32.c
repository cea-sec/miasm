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
#include "JitCore_mips32.h"



reg_dict gpreg_dict[] = { {.name = "ZERO", .offset = offsetof(struct vm_cpu, ZERO), .size = 32},
			  {.name = "AT", .offset = offsetof(struct vm_cpu, AT), .size = 32},
			  {.name = "V0", .offset = offsetof(struct vm_cpu, V0), .size = 32},
			  {.name = "V1", .offset = offsetof(struct vm_cpu, V1), .size = 32},
			  {.name = "A0", .offset = offsetof(struct vm_cpu, A0), .size = 32},
			  {.name = "A1", .offset = offsetof(struct vm_cpu, A1), .size = 32},
			  {.name = "A2", .offset = offsetof(struct vm_cpu, A2), .size = 32},
			  {.name = "A3", .offset = offsetof(struct vm_cpu, A3), .size = 32},
			  {.name = "T0", .offset = offsetof(struct vm_cpu, T0), .size = 32},
			  {.name = "T1", .offset = offsetof(struct vm_cpu, T1), .size = 32},
			  {.name = "T2", .offset = offsetof(struct vm_cpu, T2), .size = 32},
			  {.name = "T3", .offset = offsetof(struct vm_cpu, T3), .size = 32},
			  {.name = "T4", .offset = offsetof(struct vm_cpu, T4), .size = 32},
			  {.name = "T5", .offset = offsetof(struct vm_cpu, T5), .size = 32},
			  {.name = "T6", .offset = offsetof(struct vm_cpu, T6), .size = 32},
			  {.name = "T7", .offset = offsetof(struct vm_cpu, T7), .size = 32},
			  {.name = "S0", .offset = offsetof(struct vm_cpu, S0), .size = 32},
			  {.name = "S1", .offset = offsetof(struct vm_cpu, S1), .size = 32},
			  {.name = "S2", .offset = offsetof(struct vm_cpu, S2), .size = 32},
			  {.name = "S3", .offset = offsetof(struct vm_cpu, S3), .size = 32},
			  {.name = "S4", .offset = offsetof(struct vm_cpu, S4), .size = 32},
			  {.name = "S5", .offset = offsetof(struct vm_cpu, S5), .size = 32},
			  {.name = "S6", .offset = offsetof(struct vm_cpu, S6), .size = 32},
			  {.name = "S7", .offset = offsetof(struct vm_cpu, S7), .size = 32},
			  {.name = "T8", .offset = offsetof(struct vm_cpu, T8), .size = 32},
			  {.name = "T9", .offset = offsetof(struct vm_cpu, T9), .size = 32},
			  {.name = "K0", .offset = offsetof(struct vm_cpu, K0), .size = 32},
			  {.name = "K1", .offset = offsetof(struct vm_cpu, K1), .size = 32},
			  {.name = "GP", .offset = offsetof(struct vm_cpu, GP), .size = 32},
			  {.name = "SP", .offset = offsetof(struct vm_cpu, SP), .size = 32},
			  {.name = "FP", .offset = offsetof(struct vm_cpu, FP), .size = 32},
			  {.name = "RA", .offset = offsetof(struct vm_cpu, RA), .size = 32},
			  {.name = "PC", .offset = offsetof(struct vm_cpu, PC), .size = 32},
			  {.name = "PC_FETCH", .offset = offsetof(struct vm_cpu, PC_FETCH), .size = 32},
			  {.name = "R_LO", .offset = offsetof(struct vm_cpu, R_LO), .size = 32},
			  {.name = "R_HI", .offset = offsetof(struct vm_cpu, R_HI), .size = 32},
};

/************************** JitCpu object **************************/



PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg(ZERO);
    get_reg(AT);
    get_reg(V0);
    get_reg(V1);
    get_reg(A0);
    get_reg(A1);
    get_reg(A2);
    get_reg(A3);
    get_reg(T0);
    get_reg(T1);
    get_reg(T2);
    get_reg(T3);
    get_reg(T4);
    get_reg(T5);
    get_reg(T6);
    get_reg(T7);
    get_reg(S0);
    get_reg(S1);
    get_reg(S2);
    get_reg(S3);
    get_reg(S4);
    get_reg(S5);
    get_reg(S6);
    get_reg(S7);
    get_reg(T8);
    get_reg(T9);
    get_reg(K0);
    get_reg(K1);
    get_reg(GP);
    get_reg(SP);
    get_reg(FP);
    get_reg(RA);
    get_reg(PC);
    get_reg(PC_FETCH);
    get_reg(R_LO);
    get_reg(R_HI);

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

	printf("ZR %.8"PRIX32" AT %.8"PRIX32" V0 %.8"PRIX32" V1 %.8"PRIX32" ",
	       vmcpu->ZERO, vmcpu->AT, vmcpu->V0, vmcpu->V1);
	printf("A0 %.8"PRIX32" A1 %.8"PRIX32" A2 %.8"PRIX32" A3 %.8"PRIX32" ",
	       vmcpu->A0, vmcpu->A1, vmcpu->A2, vmcpu->A3);
	printf("T0 %.8"PRIX32" T1 %.8"PRIX32" T2 %.8"PRIX32" T3 %.8"PRIX32" ",
	       vmcpu->T0, vmcpu->T1, vmcpu->T2, vmcpu->T3);
	printf("T4 %.8"PRIX32" T5 %.8"PRIX32" T6 %.8"PRIX32" T7 %.8"PRIX32"\n",
	       vmcpu->T4, vmcpu->T5, vmcpu->T6, vmcpu->T7);
	printf("S0 %.8"PRIX32" S1 %.8"PRIX32" S2 %.8"PRIX32" S3 %.8"PRIX32" ",
	       vmcpu->S0, vmcpu->S1, vmcpu->S2, vmcpu->S3);
	printf("S4 %.8"PRIX32" S5 %.8"PRIX32" S6 %.8"PRIX32" S7 %.8"PRIX32" ",
	       vmcpu->S4, vmcpu->S5, vmcpu->S6, vmcpu->S7);
	printf("T8 %.8"PRIX32" T9 %.8"PRIX32" K0 %.8"PRIX32" K1 %.8"PRIX32" ",
	       vmcpu->T8, vmcpu->T9, vmcpu->K0, vmcpu->K1);
	printf("GP %.8"PRIX32" SP %.8"PRIX32" FP %.8"PRIX32" RA %.8"PRIX32"\n",
	       vmcpu->GP, vmcpu->SP, vmcpu->FP, vmcpu->RA);
	printf("PC %.8"PRIX32"\n",
	       vmcpu->PC);
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

getset_reg_u32(ZERO);
getset_reg_u32(AT);
getset_reg_u32(V0);
getset_reg_u32(V1);
getset_reg_u32(A0);
getset_reg_u32(A1);
getset_reg_u32(A2);
getset_reg_u32(A3);
getset_reg_u32(T0);
getset_reg_u32(T1);
getset_reg_u32(T2);
getset_reg_u32(T3);
getset_reg_u32(T4);
getset_reg_u32(T5);
getset_reg_u32(T6);
getset_reg_u32(T7);
getset_reg_u32(S0);
getset_reg_u32(S1);
getset_reg_u32(S2);
getset_reg_u32(S3);
getset_reg_u32(S4);
getset_reg_u32(S5);
getset_reg_u32(S6);
getset_reg_u32(S7);
getset_reg_u32(T8);
getset_reg_u32(T9);
getset_reg_u32(K0);
getset_reg_u32(K1);
getset_reg_u32(GP);
getset_reg_u32(SP);
getset_reg_u32(FP);
getset_reg_u32(RA);
getset_reg_u32(PC);
getset_reg_u32(PC_FETCH);
getset_reg_u32(R_LO);
getset_reg_u32(R_HI);


PyObject* get_gpreg_offset_all(void)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

    get_reg_off(exception_flags);


    get_reg_off(ZERO);
    get_reg_off(AT);
    get_reg_off(V0);
    get_reg_off(V1);
    get_reg_off(A0);
    get_reg_off(A1);
    get_reg_off(A2);
    get_reg_off(A3);
    get_reg_off(T0);
    get_reg_off(T1);
    get_reg_off(T2);
    get_reg_off(T3);
    get_reg_off(T4);
    get_reg_off(T5);
    get_reg_off(T6);
    get_reg_off(T7);
    get_reg_off(S0);
    get_reg_off(S1);
    get_reg_off(S2);
    get_reg_off(S3);
    get_reg_off(S4);
    get_reg_off(S5);
    get_reg_off(S6);
    get_reg_off(S7);
    get_reg_off(T8);
    get_reg_off(T9);
    get_reg_off(K0);
    get_reg_off(K1);
    get_reg_off(GP);
    get_reg_off(SP);
    get_reg_off(FP);
    get_reg_off(RA);
    get_reg_off(PC);
    get_reg_off(PC_FETCH);
    get_reg_off(R_LO);
    get_reg_off(R_HI);

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

    {"ZERO" , (getter)JitCpu_get_ZERO , (setter)JitCpu_set_ZERO , "ZERO" , NULL},
    {"AT" , (getter)JitCpu_get_AT , (setter)JitCpu_set_AT , "AT" , NULL},
    {"V0" , (getter)JitCpu_get_V0 , (setter)JitCpu_set_V0 , "V0" , NULL},
    {"V1" , (getter)JitCpu_get_V1 , (setter)JitCpu_set_V1 , "V1" , NULL},
    {"A0" , (getter)JitCpu_get_A0 , (setter)JitCpu_set_A0 , "A0" , NULL},
    {"A1" , (getter)JitCpu_get_A1 , (setter)JitCpu_set_A1 , "A1" , NULL},
    {"A2" , (getter)JitCpu_get_A2 , (setter)JitCpu_set_A2 , "A2" , NULL},
    {"A3" , (getter)JitCpu_get_A3 , (setter)JitCpu_set_A3 , "A3" , NULL},
    {"T0" , (getter)JitCpu_get_T0 , (setter)JitCpu_set_T0 , "T0" , NULL},
    {"T1" , (getter)JitCpu_get_T1 , (setter)JitCpu_set_T1 , "T1" , NULL},
    {"T2" , (getter)JitCpu_get_T2 , (setter)JitCpu_set_T2 , "T2" , NULL},
    {"T3" , (getter)JitCpu_get_T3 , (setter)JitCpu_set_T3 , "T3" , NULL},
    {"T4" , (getter)JitCpu_get_T4 , (setter)JitCpu_set_T4 , "T4" , NULL},
    {"T5" , (getter)JitCpu_get_T5 , (setter)JitCpu_set_T5 , "T5" , NULL},
    {"T6" , (getter)JitCpu_get_T6 , (setter)JitCpu_set_T6 , "T6" , NULL},
    {"T7" , (getter)JitCpu_get_T7 , (setter)JitCpu_set_T7 , "T7" , NULL},
    {"S0" , (getter)JitCpu_get_S0 , (setter)JitCpu_set_S0 , "S0" , NULL},
    {"S1" , (getter)JitCpu_get_S1 , (setter)JitCpu_set_S1 , "S1" , NULL},
    {"S2" , (getter)JitCpu_get_S2 , (setter)JitCpu_set_S2 , "S2" , NULL},
    {"S3" , (getter)JitCpu_get_S3 , (setter)JitCpu_set_S3 , "S3" , NULL},
    {"S4" , (getter)JitCpu_get_S4 , (setter)JitCpu_set_S4 , "S4" , NULL},
    {"S5" , (getter)JitCpu_get_S5 , (setter)JitCpu_set_S5 , "S5" , NULL},
    {"S6" , (getter)JitCpu_get_S6 , (setter)JitCpu_set_S6 , "S6" , NULL},
    {"S7" , (getter)JitCpu_get_S7 , (setter)JitCpu_set_S7 , "S7" , NULL},
    {"T8" , (getter)JitCpu_get_T8 , (setter)JitCpu_set_T8 , "T8" , NULL},
    {"T9" , (getter)JitCpu_get_T9 , (setter)JitCpu_set_T9 , "T9" , NULL},
    {"K0" , (getter)JitCpu_get_K0 , (setter)JitCpu_set_K0 , "K0" , NULL},
    {"K1" , (getter)JitCpu_get_K1 , (setter)JitCpu_set_K1 , "K1" , NULL},
    {"GP" , (getter)JitCpu_get_GP , (setter)JitCpu_set_GP , "GP" , NULL},
    {"SP" , (getter)JitCpu_get_SP , (setter)JitCpu_set_SP , "SP" , NULL},
    {"FP" , (getter)JitCpu_get_FP , (setter)JitCpu_set_FP , "FP" , NULL},
    {"RA" , (getter)JitCpu_get_RA , (setter)JitCpu_set_RA , "RA" , NULL},
    {"PC" , (getter)JitCpu_get_PC , (setter)JitCpu_set_PC , "PC" , NULL},
    {"PC_FETCH" , (getter)JitCpu_get_PC_FETCH , (setter)JitCpu_set_PC_FETCH , "PC_FETCH" , NULL},
    {"R_LO" , (getter)JitCpu_get_R_LO , (setter)JitCpu_set_R_LO , "R_LO" , NULL},
    {"R_HI" , (getter)JitCpu_get_R_HI , (setter)JitCpu_set_R_HI , "R_HI" , NULL},

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "JitCore_mips32.JitCpu",   /*tp_name*/
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



static PyMethodDef JitCore_mips32_Methods[] = {

	/*

	*/
	{"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
	{NULL, NULL, 0, NULL}        /* Sentinel */

};





MOD_INIT(JitCore_mips32)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_mips32", "JitCore_mips32 module", JitCore_mips32_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}
