#include <Python.h>

#include <inttypes.h>

#include <stdint.h>
#include "queue.h"
#include "vm_mngr.h"
#include "vm_mngr_py.h"
#include "JitCore.h"
// Needed to get the JitCpu.cpu offset, arch independent
#include "arch/JitCore_x86.h"

PyObject* llvm_exec_bloc(PyObject* self, PyObject* args)
{
	uint64_t (*func)(void*, void*, void*, uint8_t*);
	vm_cpu_t* cpu;
	vm_mngr_t* vm;
	uint64_t ret;
	JitCpu* jitcpu;
	uint8_t status;
	PyObject* func_py;
	PyObject* lbl2ptr;
	PyObject* breakpoints;
	PyObject* retaddr = NULL;
	uint64_t max_exec_per_call = 0;
	uint64_t cpt;
	int do_cpt;

	if (!PyArg_ParseTuple(args, "OOOO|K",
			      &retaddr, &jitcpu, &lbl2ptr, &breakpoints,
			      &max_exec_per_call))
		return NULL;

	cpu = jitcpu->cpu;
	vm = &(jitcpu->pyvm->vm_mngr);
	/* The loop will decref retaddr always once */
	Py_INCREF(retaddr);

	if (max_exec_per_call == 0) {
		do_cpt = 0;
		cpt = 1;
	} else {
		do_cpt = 1;
		cpt = max_exec_per_call;
	}

	for (;;) {
		// Handle cpt
		if (cpt == 0)
			return retaddr;
		if (do_cpt)
			cpt --;

		// Get the expected jitted function address
		func_py = PyDict_GetItem(lbl2ptr, retaddr);
		if (func_py)
			func = PyLong_AsVoidPtr((PyObject*) func_py);
		else
			// retaddr is not jitted yet
			return retaddr;

		// Execute it
		ret = func((void*) jitcpu, (void*)(intptr_t) cpu, (void*)(intptr_t) vm, &status);
		Py_DECREF(retaddr);
		retaddr = PyLong_FromUnsignedLongLong(ret);

		// Check exception
		if (status)
			return retaddr;

		// Check breakpoint
		if (PyDict_Contains(breakpoints, retaddr))
			return retaddr;
	}
}


static PyMethodDef LLVMMethods[] = {
    {"llvm_exec_bloc",  llvm_exec_bloc, METH_VARARGS,
     "llvm exec bloc"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initJitllvm(void)
{
    PyObject *m;

    m = Py_InitModule("Jitllvm", LLVMMethods);
    if (m == NULL)
	    return;

}
