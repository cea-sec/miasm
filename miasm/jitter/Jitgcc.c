#include <Python.h>
#include <inttypes.h>
#include <stdint.h>
#include "compat_py23.h"

typedef struct {
	uint8_t is_local;
	uint64_t address;
} block_id;

typedef int (*jitted_func)(block_id*, PyObject*);


PyObject* gcc_exec_block(PyObject* self, PyObject* args)
{
	jitted_func func;
	PyObject* jitcpu;
	PyObject* func_py;
	PyObject* lbl2ptr;
	PyObject* stop_offsets;
	PyObject* retaddr = NULL;
	int status;
	block_id BlockDst;
	uint64_t max_exec_per_call = 0;
	uint64_t cpt;
	int do_cpt;


	if (!PyArg_ParseTuple(args, "OOOO|K",
			      &retaddr, &jitcpu, &lbl2ptr, &stop_offsets,
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

		// Check stop offsets
		if (PySet_Contains(stop_offsets, retaddr))
			return retaddr;
	}
}



static PyMethodDef GccMethods[] = {
    {"gcc_exec_block",  gcc_exec_block, METH_VARARGS,
     "gcc exec block"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};



MOD_INIT(Jitgcc)
{
	PyObject *module = NULL;

	MOD_DEF(module, "Jitgcc", "gcc module", GccMethods);

	RET_MODULE;
}
