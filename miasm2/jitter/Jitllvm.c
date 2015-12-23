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
	uint64_t func_addr;
	uint64_t (*func)(void*, void*);
	uint64_t vm;
	uint64_t ret;
	JitCpu* jitcpu;

	if (!PyArg_ParseTuple(args, "KOK", &func_addr, &jitcpu, &vm))
		return NULL;
	vm_cpu_t* cpu = jitcpu->cpu;
	func = (void *) (intptr_t) func_addr;
	ret = func((void*)(intptr_t) cpu, (void*)(intptr_t) vm);
	return PyLong_FromUnsignedLongLong(ret);
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
