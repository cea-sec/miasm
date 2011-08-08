/*
** Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License along
** with this program; if not, write to the Free Software Foundation, Inc.,
** 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <Python.h>

#include <libtcc.h>



/* tcc global state */
TCCState *tcc_state = NULL;


char *emul_lib_dir = NULL;
char *emul_lib_path = NULL;
char *emul_libpython_dir = NULL;

PyObject* tcc_set_emul_lib_path(PyObject* self, PyObject* args)
{
	char* libdir;
	char* libpath;
	char* libpython_dir;
	if (!PyArg_ParseTuple(args, "sss", &libdir, &libpath, &libpython_dir))
		return NULL;
	emul_lib_dir = (char*)malloc(strlen(libdir)+1);
	emul_lib_path = (char*)malloc(strlen(libpath)+1);
	emul_libpython_dir = (char*)malloc(strlen(libpython_dir)+1);
	strcpy(emul_lib_dir, libdir);
	strcpy(emul_lib_path, libpath);
	strcpy(emul_libpython_dir, libpython_dir);
	return Py_None;
}

void tcc_init_state(void)
{
	tcc_state = tcc_new();
	if (!tcc_state) {
		fprintf(stderr, "Impossible de creer un contexte TCC\n");
		exit(1);
	}
	tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

	tcc_add_include_path(tcc_state, emul_libpython_dir);
	tcc_add_include_path(tcc_state, emul_lib_dir);
	tcc_add_file(tcc_state, emul_lib_path);
}




PyObject*  tcc_exec_bloc(PyObject* self, PyObject* args)
{
	int (*func)(void);

	unsigned long ret;
	if (!PyArg_ParseTuple(args, "i", &func))
		return NULL;
	ret = func();
	return PyInt_FromLong((long)ret);
}

PyObject* tcc_compil(PyObject* self, PyObject* args)
{
	char* func_name;
	char* func_code;
	int (*entry)(void);

	if (!PyArg_ParseTuple(args, "ss", &func_name, &func_code))
		return NULL;

	tcc_init_state();
	if (tcc_compile_string(tcc_state, func_code) != 0) {
		printf("Erreur de compilation !\n");
		exit(0);
	}
	/* XXX use tinycc devel with -fPIC patch in makefile */
	if (tcc_relocate(tcc_state) < 0)
		exit(0);
	entry = tcc_get_symbol(tcc_state, func_name);

	return PyInt_FromLong((long)entry);

}


static PyObject *TccError;


static PyMethodDef TccMethods[] = {
    {"tcc_set_emul_lib_path",  tcc_set_emul_lib_path, METH_VARARGS,
     "init tcc path"},
    {"tcc_exec_bloc",  tcc_exec_bloc, METH_VARARGS,
     "tcc exec bloc"},
    {"tcc_compil",  tcc_compil, METH_VARARGS,
     "tcc compil"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initlibcodenat_tcc(void)
{
    PyObject *m;

    m = Py_InitModule("libcodenat_tcc", TccMethods);
    if (m == NULL)
	    return;

    TccError = PyErr_NewException("tcc.error", NULL, NULL);
    Py_INCREF(TccError);
    PyModule_AddObject(m, "error", TccError);
}

