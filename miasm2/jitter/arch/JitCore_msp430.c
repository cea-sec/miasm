#include <Python.h>
#include "JitCore.h"
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include "JitCore_msp430.h"

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}

/*
void check_align(uint64_t addr)
{
	if (addr & 1) {
		printf("unaligned mem lookup %X\n", addr);
		exit(0);
	}
}

void VM_MEM_WRITE_08(vm_mngr_t* vm_mngr, uint64_t addr, unsigned char src)
{
	//check_align(addr);
	MEM_WRITE_08(vm_mngr, addr, src);
}

void VM_MEM_WRITE_16(vm_mngr_t* vm_mngr, uint64_t addr, unsigned short src)
{
	check_align(addr);
	MEM_WRITE_16(vm_mngr, addr, src);
}

void VM_MEM_WRITE_32(vm_mngr_t* vm_mngr, uint64_t addr, unsigned int src)
{
	check_align(addr);
	MEM_WRITE_32(vm_mngr, addr, src);
}

void VM_MEM_WRITE_64(vm_mngr_t* vm_mngr, uint64_t addr, uint64_t src)
{
	check_align(addr);
	MEM_WRITE_64(vm_mngr, addr, src);
}
*/

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

reg_dict gpreg_dict[] = { {.name = "PC", .offset = offsetof(vm_cpu_t, PC)},
			  {.name = "SP", .offset = offsetof(vm_cpu_t, SP)},
			  //{.name = "SR", .offset = offsetof(vm_cpu_t, SR)},
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
			  {.name = "R13", .offset = offsetof(vm_cpu_t, R13)},
			  {.name = "R14", .offset = offsetof(vm_cpu_t, R14)},
			  {.name = "R15", .offset = offsetof(vm_cpu_t, R15)},

			  {.name = "zf", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "nf", .offset = offsetof(vm_cpu_t, nf)},
			  {.name = "of", .offset = offsetof(vm_cpu_t, of)},
			  {.name = "cf", .offset = offsetof(vm_cpu_t, cf)},

			  {.name = "cpuoff", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "gie", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "osc", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "scg0", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "scg1", .offset = offsetof(vm_cpu_t, zf)},
			  {.name = "res", .offset = offsetof(vm_cpu_t, zf)},

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
    get_reg_off(PC_new);
    get_reg_off(SP_new);
    get_reg_off(SR_new);
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
    get_reg_off(R13_new);
    get_reg_off(R14_new);
    get_reg_off(R15_new);
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
    get_reg_off(zf_new);
    get_reg_off(nf_new);
    get_reg_off(of_new);
    get_reg_off(cf_new);
    get_reg_off(cpuoff_new);
    get_reg_off(gie_new);
    get_reg_off(osc_new);
    get_reg_off(scg0_new);
    get_reg_off(scg1_new);
    get_reg_off(res_new);
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

uint8_t const bcd2bin_data[] = {
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 0, 0, 0, 0, 0, 0,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0, 0, 0, 0, 0,
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 0, 0, 0, 0, 0, 0,
	30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 0, 0, 0, 0, 0, 0,
	40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0, 0,
	50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 0, 0, 0, 0, 0, 0,
	60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 0, 0, 0, 0, 0, 0,
	70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 0, 0, 0, 0, 0, 0,
	80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 0, 0, 0, 0, 0, 0,
	90, 91, 92, 93, 94, 95, 96, 97, 98, 99
};

uint8_t const bin2bcd_data[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99
};

inline uint16_t bcdadd_16(uint16_t a, uint16_t b)
{
	int carry = 0;
	int i,j = 0;
	uint16_t res = 0;
	int nib_a, nib_b;
	for (i = 0; i < 16; i += 4) {
		nib_a = (a  >> i) & (0xF);
		nib_b = (b >> i) & (0xF);

		j = (carry + nib_a + nib_b);
		if (j >= 10) {
			carry = 1;
			j -= 10;
			j &=0xf;
		}
		else {
			carry = 0;
		}
		res += j << i;
	}
	return res;
}

inline uint16_t bcdadd_cf_16(uint16_t a, uint16_t b)
{
	int carry = 0;
	int i,j = 0;
	int nib_a, nib_b;
	for (i = 0; i < 16; i += 4) {
		nib_a = (a >> i) & (0xF);
		nib_b = (b >> i) & (0xF);

		j = (carry + nib_a + nib_b);
		if (j >= 10) {
			carry = 1;
			j -= 10;
			j &=0xf;
		}
		else {
			carry = 0;
		}
	}
	return carry;
}


inline uint16_t hex2bcd_16(uint16_t a)
{
	return bcd2bin_data[a & 0xFF] + (bcd2bin_data[(a >> 8) & 0xFF] * 100);
}

inline uint8_t hex2bcd_8(uint8_t a)
{
	return bcd2bin_data[a & 0xFF];
}

inline uint8_t bcd2hex_8(uint8_t a)
{
	return bin2bcd_data[a & 0xFF];
}

inline uint16_t bcd2hex_16(uint16_t a)
{
	return bcd2bin_data[a % 100] | (bcd2bin_data[(a / 100)] << 8);
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

	printf("PC  %.4"PRIX32" SP  %.4"PRIX32"  R3  %.4"PRIX32" ",
	       vmcpu->PC, vmcpu->SP, vmcpu->R3);
	printf("R4  %.4"PRIX32" R5  %.4"PRIX32" R6  %.4"PRIX32" R7  %.4"PRIX32"\n",
	       vmcpu->R4, vmcpu->R5, vmcpu->R6, vmcpu->R7);
	printf("R8  %.4"PRIX32" R9  %.4"PRIX32" R10 %.4"PRIX32" R11 %.4"PRIX32" ",
	       vmcpu->R8, vmcpu->R9, vmcpu->R10, vmcpu->R11);
	printf("R12 %.4"PRIX32" R13 %.4"PRIX32" R14 %.4"PRIX32" R15 %.4"PRIX32"\n",
	       vmcpu->R12, vmcpu->R13, vmcpu->R14, vmcpu->R15);
	printf("zf %.4"PRIX32" nf %.4"PRIX32" of %.4"PRIX32" cf %.4"PRIX32"\n",
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


	fprintf(stderr, "ad cpu: %p\n", &(self->vmcpu));

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




static PyGetSetDef JitCpu_getseters[] = {
    {"cpu",
     (getter)JitCpu_get_cpu, (setter)JitCpu_set_cpu,
     "first name",
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
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
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

static PyObject *JitCore_msp430_Error;

PyMODINIT_FUNC
initJitCore_msp430(void)
{
    PyObject *m;

    if (PyType_Ready(&JitCpuType) < 0)
	return;

    m = Py_InitModule("JitCore_msp430", JitCore_msp430_Methods);
    if (m == NULL)
	    return;

    JitCore_msp430_Error = PyErr_NewException("JitCore_msp430.error", NULL, NULL);
    Py_INCREF(JitCore_msp430_Error);
    PyModule_AddObject(m, "error", JitCore_msp430_Error);

    Py_INCREF(&JitCpuType);
    PyModule_AddObject(m, "JitCpu", (PyObject *)&JitCpuType);

}

