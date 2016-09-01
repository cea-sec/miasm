#include <Python.h>
#include "structmember.h"
#include <stdint.h>
#include <inttypes.h>
#include "queue.h"
#include "vm_mngr.h"
#include "vm_mngr_py.h"
#include "JitCore.h"


void JitCpu_dealloc(JitCpu* self)
{
    self->ob_type->tp_free((PyObject*)self);
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

uint8_t __attribute__((weak)) MEM_LOOKUP_08(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_08(&(jitcpu->pyvm->vm_mngr), addr);
}

uint16_t __attribute__((weak)) MEM_LOOKUP_16(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_16(&(jitcpu->pyvm->vm_mngr), addr);
}

uint32_t __attribute__((weak)) MEM_LOOKUP_32(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_32(&(jitcpu->pyvm->vm_mngr), addr);
}

uint64_t __attribute__((weak)) MEM_LOOKUP_64(JitCpu* jitcpu, uint64_t addr)
{
	return vm_MEM_LOOKUP_64(&(jitcpu->pyvm->vm_mngr), addr);
}

void __attribute__((weak)) MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src)
{
	vm_MEM_WRITE_08(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void __attribute__((weak)) MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src)
{
	vm_MEM_WRITE_16(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void __attribute__((weak)) MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src)
{
	vm_MEM_WRITE_32(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}

void __attribute__((weak)) MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src)
{
	vm_MEM_WRITE_64(&((VmMngr*)jitcpu->pyvm)->vm_mngr, addr, src);
}




PyObject* __attribute__((weak)) vm_get_mem(JitCpu *self, PyObject* args)
{
       PyObject *py_addr;
       PyObject *py_len;

       uint64_t addr;
       uint64_t size;
       PyObject *obj_out;
       char * buf_out;
       int ret;

       if (!PyArg_ParseTuple(args, "OO", &py_addr, &py_len))
	       return NULL;

       PyGetInt(py_addr, addr);
       PyGetInt(py_len, size);

       ret = vm_read_mem(&(((VmMngr*)self->pyvm)->vm_mngr), addr, &buf_out, size);
       if (ret < 0) {
	       PyErr_SetString(PyExc_RuntimeError, "cannot find address");
	       return NULL;
       }

       obj_out = PyString_FromStringAndSize(buf_out, size);
       free(buf_out);
       return obj_out;
}
