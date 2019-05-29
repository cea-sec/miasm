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
#include "JitCore_ppc32.h"

reg_dict gpreg_dict[] = {
#define JITCORE_PPC_REG_EXPAND(_name, _size)				\
    { .name = #_name, .offset = offsetof(struct vm_cpu, _name), .size = _size },
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND
};

PyObject* cpu_get_gpreg(JitCpu* self)
{
    PyObject *dict = PyDict_New();
    PyObject *o;

#define JITCORE_PPC_REG_EXPAND(_name, _size) \
    get_reg(_name);
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

    return dict;
}



PyObject *
cpu_set_gpreg(JitCpu *self, PyObject *args) {
    PyObject *dict;
    PyObject *d_key, *d_value = NULL;
    Py_ssize_t pos = 0;
    const char *d_key_name;
    uint32_t val;
    unsigned int i;

    if (!PyArg_ParseTuple(args, "O", &dict))
	return NULL;
    if(!PyDict_Check(dict))
	RAISE(PyExc_TypeError, "arg must be dict");

    while(PyDict_Next(dict, &pos, &d_key, &d_value)) {
	int found = 0;
	PyGetStr(d_key_name, d_key);
	PyGetInt_uint32_t(d_value, val);

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


PyObject *
cpu_init_regs(JitCpu *self) {
    memset(self->cpu, 0, sizeof(struct vm_cpu));

    Py_INCREF(Py_None);
    return Py_None;
}

static void
dump_gpreg(const char *name, uint32_t val, int *n) {
    printf("%6s %.8" PRIX32"%c", name, val, (*n + 1) % 4 == 0? '\n':' ');
    *n = (*n + 1) % 4;
}

void
dump_gpregs(struct vm_cpu *vmcpu) {
    int reg_num = 0;

#define JITCORE_PPC_REG_EXPAND(_name, _size) \
    dump_gpreg(#_name, vmcpu->_name, &reg_num);
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

    if ((reg_num % 4) != 0)
      putchar('\n');
}


PyObject *
cpu_dump_gpregs(JitCpu *self, PyObject *args) {

    dump_gpregs(self->cpu);

    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *
cpu_dump_gpregs_with_attrib(JitCpu* self, PyObject* args)
{
	return cpu_dump_gpregs(self, args);
}

PyObject *
cpu_set_exception(JitCpu *self, PyObject *args) {
    PyObject *item1;
    uint64_t exception_flags;

    if (!PyArg_ParseTuple(args, "O", &item1))
	return NULL;

    PyGetInt_uint64_t(item1, exception_flags);

    ((struct vm_cpu *)self->cpu)->exception_flags = exception_flags;

    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *
cpu_get_exception(JitCpu *self, PyObject *args) {
    return PyLong_FromUnsignedLongLong(((struct vm_cpu *)self->cpu)->exception_flags);
}

static PyObject *
cpu_get_spr_access(JitCpu *self, PyObject *args) {
    return PyLong_FromUnsignedLongLong(((struct vm_cpu *) self->cpu)->spr_access);
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
    {"init_regs", (PyCFunction)cpu_init_regs, METH_NOARGS, "X"},
    {"dump_gpregs", (PyCFunction)cpu_dump_gpregs, METH_NOARGS, "X"},
    {"dump_gpregs_with_attrib", (PyCFunction)cpu_dump_gpregs_with_attrib, METH_VARARGS, "X"},
    {"get_gpreg", (PyCFunction)cpu_get_gpreg, METH_NOARGS, "X"},
    {"set_gpreg", (PyCFunction)cpu_set_gpreg, METH_VARARGS, "X"},
    {"get_exception", (PyCFunction)cpu_get_exception, METH_VARARGS, "X"},
    {"set_exception", (PyCFunction)cpu_set_exception, METH_VARARGS, "X"},
    {"get_spr_access", (PyCFunction)cpu_get_spr_access, METH_VARARGS, "X"},
    {NULL}  /* Sentinel */
};

static int
JitCpu_init(JitCpu *self, PyObject *args, PyObject *kwds) {
    self->cpu = malloc(sizeof(struct vm_cpu));
    if (self->cpu == NULL) {
	fprintf(stderr, "cannot alloc struct vm_cpu\n");
	exit(1);
    }
    return 0;
}


#define JITCORE_PPC_REG_EXPAND(_name, _size) \
getset_reg_u32(_name);
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

PyObject *
get_gpreg_offset_all(void) {
    PyObject *dict = PyDict_New();
    PyObject *o;

#define JITCORE_PPC_REG_EXPAND(_name, _size)				\
    get_reg_off(_name);
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

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

#define JITCORE_PPC_REG_EXPAND(_name, _size)				\
    { #_name, (getter) JitCpu_get_ ## _name ,				\
	(setter) JitCpu_set_ ## _name , #_name , NULL},
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

    {NULL}  /* Sentinel */
};


static PyTypeObject JitCpuType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "JitCore_ppc.JitCpu",      /*tp_name*/
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



static PyMethodDef JitCore_ppc32_Methods[] = {
    {"get_gpreg_offset_all", (PyCFunction)get_gpreg_offset_all, METH_NOARGS},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};



MOD_INIT(JitCore_ppc32)
{
	PyObject *module = NULL;

	MOD_DEF(module, "JitCore_ppc32", "JitCore_ppc32 module", JitCore_ppc32_Methods);

	if (module == NULL)
		RET_MODULE;

	if (PyType_Ready(&JitCpuType) < 0)
		RET_MODULE;

	Py_INCREF(&JitCpuType);
	if (PyModule_AddObject(module, "JitCpu", (PyObject *)&JitCpuType) < 0)
		RET_MODULE;

	RET_MODULE;
}
