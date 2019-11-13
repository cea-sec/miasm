#include <Python.h>
#include "structmember.h"
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include "compat_py23.h"
#include "queue.h"
#include "vm_mngr.h"
#include "bn.h"
#include "vm_mngr_py.h"
#include "JitCore.h"


void JitCpu_dealloc(JitCpu* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}


PyObject * JitCpu_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    JitCpu *self;

    self = (JitCpu *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

PyObject * JitCpu_get_vmmngr(JitCpu *self, void *closure)
{
	if (self->pyvm) {
		Py_INCREF(self->pyvm);
		return (PyObject*)self->pyvm;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject * JitCpu_set_vmmngr(JitCpu *self, PyObject *value, void *closure)
{
	self->pyvm = (VmMngr*)value;
	return 0;
}



PyObject * JitCpu_get_vmcpu(JitCpu *self, void *closure)
{
	PyObject * ret;
	uint64_t addr;
	addr = (uint64_t) self->cpu;
	ret = PyLong_FromUnsignedLongLong(addr);
	return ret;
}

PyObject * JitCpu_set_vmcpu(JitCpu *self, PyObject *value, void *closure)
{
	fprintf(stderr, "Set vmcpu not supported yet\n");
	exit(-1);
}



PyObject * JitCpu_get_jitter(JitCpu *self, void *closure)
{
	if (self->jitter) {
		Py_INCREF(self->jitter);
		return self->jitter;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject * JitCpu_set_jitter(JitCpu *self, PyObject *value, void *closure)
{
	self->jitter = value;
	return 0;
}

uint8_t MEM_LOOKUP_08(JitCpu* jitcpu, uint64_t addr)
{
    return vm_MEM_LOOKUP_08(&(jitcpu->pyvm->vm_mngr), addr);
}

uint16_t MEM_LOOKUP_16(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_16(&(jitcpu->pyvm->vm_mngr), addr);
}

uint32_t MEM_LOOKUP_32(JitCpu* jitcpu, uint64_t addr)
{
    return vm_MEM_LOOKUP_32(&(jitcpu->pyvm->vm_mngr), addr);
}

uint64_t MEM_LOOKUP_64(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_64(&(jitcpu->pyvm->vm_mngr), addr);
}

bn_t MEM_LOOKUP_BN_BN(JitCpu* jitcpu, int size, bn_t addr)
{
	uint64_t ptr;
	int i;
	uint8_t tmp;
	bn_t val = bignum_from_int(0);

	ptr = bignum_to_uint64(addr);


	for (i=0; i < size; i += 8) {
		tmp = vm_MEM_LOOKUP_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr);
		ptr += 1;
		val = bignum_or(val, bignum_lshift(bignum_from_int(tmp), i));
	}

	return val;
}


uint64_t MEM_LOOKUP_BN_INT(JitCpu* jitcpu, int size, bn_t addr)
{
	uint64_t ptr;
	uint64_t val = 0;

	ptr = bignum_to_uint64(addr);

	switch (size) {
		case 8:
			val = vm_MEM_LOOKUP_08(&(jitcpu->pyvm->vm_mngr), ptr);
			break;
		case 16:
			val = vm_MEM_LOOKUP_16(&(jitcpu->pyvm->vm_mngr), ptr);
			break;
		case 32:
			val = vm_MEM_LOOKUP_32(&(jitcpu->pyvm->vm_mngr), ptr);
			break;
		case 64:
			val = vm_MEM_LOOKUP_64(&(jitcpu->pyvm->vm_mngr), ptr);
			break;
		default:
			fprintf(stderr, "Error: bad READ size %d\n", size);
			exit(-1);
			break;
	}

	return val;
}



bn_t MEM_LOOKUP_INT_BN(JitCpu* jitcpu, int size, uint64_t addr)
{
	int i;
	uint8_t tmp;
	bn_t val = bignum_from_int(0);

	for (i=0; i < size; i += 8) {
		tmp = vm_MEM_LOOKUP_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr);
		addr += 1;
		val = bignum_or(val, bignum_lshift(bignum_from_int(tmp), i));
	}

	return val;
}


void MEM_LOOKUP_INT_BN_TO_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr)
{
	bn_t ret;

	if (size % 8) {
		fprintf(stderr, "Bad size %d\n", size);
		exit(-1);
	}

	ret = MEM_LOOKUP_INT_BN(jitcpu, size, addr);
	memcpy(ptr, (char*)&ret, size / 8);
}


void MEM_WRITE_BN_BN(JitCpu* jitcpu, int size, bn_t addr, bn_t src)
{
	uint64_t ptr;
	int val;
	int i;

	ptr = bignum_to_uint64(addr);
	for (i=0; i < size; i += 8) {
		val = bignum_to_uint64(src) & 0xFF;
		vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr, val);
		ptr += 1;
		src = bignum_rshift(src, 8);
	}
}


void MEM_WRITE_BN_INT(JitCpu* jitcpu, int size, bn_t addr, uint64_t src)
{
	uint64_t ptr;
	ptr = bignum_to_uint64(addr);

	switch (size) {
		case 8:
			vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr, (unsigned char)src);
			break;
		case 16:
			vm_MEM_WRITE_16(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr, (unsigned short)src);
			break;
		case 32:
			vm_MEM_WRITE_32(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr, (unsigned int)src);
			break;
		case 64:
			vm_MEM_WRITE_64(&((VmMngr*)jitcpu->pyvm)->vm_mngr, ptr, src);
			break;
		default:
			fprintf(stderr, "Error: bad write size %d\n", size);
			exit(-1);
			break;
	}
}

void MEM_WRITE_INT_BN(JitCpu* jitcpu, int size, uint64_t addr, bn_t src)
{
	int val;
	int i;

	for (i=0; i < size; i += 8) {
		val = bignum_to_uint64(src) & 0xFF;
		vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, val);
		addr += 1;
		src = bignum_rshift(src, 8);
	}
}


void MEM_WRITE_INT_BN_FROM_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr)
{
	bn_t val;

	if (size % 8) {
		fprintf(stderr, "Bad size %d\n", size);
		exit(-1);
	}

	val = bignum_from_int(0);
	memcpy(&val, ptr, size / 8);
	MEM_WRITE_INT_BN(jitcpu, size, addr, val);
}
