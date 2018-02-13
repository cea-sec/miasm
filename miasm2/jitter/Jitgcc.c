#include <Python.h>
#include <inttypes.h>
#include <stdint.h>

typedef struct {
	uint8_t is_local;
	uint64_t address;
} block_id;

typedef int (*jitted_func)(block_id*, PyObject*);


PyObject* gcc_exec_bloc(PyObject* self, PyObject* args)
{
	jitted_func func;
	PyObject* jitcpu;
	PyObject* func_py;
	PyObject* lbl2ptr;
	PyObject* breakpoints;
	PyObject* retaddr = NULL;
	int status;
	block_id BlockDst;
	uint64_t max_exec_per_call = 0;
	uint64_t cpt;
	int do_cpt;


	if (!PyArg_ParseTuple(args, "OOOO|K",
			      &retaddr, &jitcpu, &lbl2ptr, &breakpoints,
			      &max_exec_per_call))
		return NULL;

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
		if (cpt == 0)
			return retaddr;
		if (do_cpt)
			cpt --;
		// Init
		BlockDst.is_local = 0;
		BlockDst.address = 0;

		// Get the expected jitted function address
		func_py = PyDict_GetItem(lbl2ptr, retaddr);
		if (func_py)
			func = (jitted_func) PyLong_AsVoidPtr((PyObject*) func_py);
		else {
			if (BlockDst.is_local == 1) {
				fprintf(stderr, "return on local label!\n");
				exit(EXIT_FAILURE);
			}
			// retaddr is not jitted yet
			return retaddr;
		}
		// Execute it
		status = func(&BlockDst, jitcpu);
		Py_DECREF(retaddr);
		retaddr = PyLong_FromUnsignedLongLong(BlockDst.address);

		// Check exception
		if (status)
			return retaddr;

		// Check breakpoint
		if (PyDict_Contains(breakpoints, retaddr))
			return retaddr;
	}
}



static PyObject *GccError;


static PyMethodDef GccMethods[] = {
    {"gcc_exec_bloc",  gcc_exec_bloc, METH_VARARGS,
     "gcc exec bloc"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initJitgcc(void)
{
    PyObject *m;

    m = Py_InitModule("Jitgcc", GccMethods);
    if (m == NULL)
	    return;

    GccError = PyErr_NewException("gcc.error", NULL, NULL);
    Py_INCREF(GccError);
    PyModule_AddObject(m, "error", GccError);
}

