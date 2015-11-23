#include <Python.h>

#include <inttypes.h>

#include <stdint.h>

PyObject* llvm_exec_bloc(PyObject* self, PyObject* args)
{
	uint64_t func_addr;
	uint64_t (*func)(void*, void*);
	uint64_t vm;
	uint64_t cpu;
	uint64_t ret;

	if (!PyArg_ParseTuple(args, "KKK", &func_addr, &cpu, &vm))
		return NULL;
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
