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

#include <inttypes.h>
#include <libtcc.h>



/* tcc global state */
TCCState *tcc_state = NULL;


int include_path_array_count = 0;
char **include_path_array = NULL;

char *libcodenat_path = NULL;

PyObject* tcc_set_emul_lib_path(PyObject* self, PyObject* args)
{
	char* include_path_arg;
	char* libcodenat_path_arg;

	char* str1, * str2;

	if (!PyArg_ParseTuple(args, "ss",
			      &include_path_arg,
			      &libcodenat_path_arg))
		return NULL;

	if (include_path_array)
		free(include_path_array);

	str2 = strdup(include_path_arg);
	while (str2){
		str1 = strsep(&str2, ";");
		if (str1){
			include_path_array_count ++;
			include_path_array = realloc(include_path_array,
						     include_path_array_count * sizeof(char*));
			include_path_array[include_path_array_count-1] = strdup(str1);
			printf("adding include file: %s\n", str1);
		}
	}

	libcodenat_path = (char*)malloc(strlen(libcodenat_path_arg)+1);
	strcpy(libcodenat_path, libcodenat_path_arg);
	return Py_None;
}

void tcc_init_state(void)
{
	int i;
	tcc_state = tcc_new();
	if (!tcc_state) {
		fprintf(stderr, "Impossible de creer un contexte TCC\n");
		exit(1);
	}
	tcc_set_output_type(tcc_state, TCC_OUTPUT_MEMORY);

	tcc_add_file(tcc_state, libcodenat_path);
	for (i=0;i<include_path_array_count; i++){
		tcc_add_include_path(tcc_state, include_path_array[i]);
	}
}




PyObject*  tcc_exec_bloc(PyObject* self, PyObject* args)
{
	uint64_t (*func)(void);

	unsigned long ret;
	if (!PyArg_ParseTuple(args, "l", &func))
		return NULL;
	ret = func();
	return PyLong_FromUnsignedLong(ret);
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
		fprintf(stderr, "Erreur de compilation !\n");
		fprintf(stderr, "%s\n", func_code);
		exit(0);
	}
	/* XXX use tinycc devel with -fPIC patch in makefile */
	if (tcc_relocate(tcc_state,TCC_RELOCATE_AUTO) < 0)
		exit(0);
	entry = tcc_get_symbol(tcc_state, func_name);
	if (!entry){
		fprintf(stderr, "Erreur de symbole !\n");
		fprintf(stderr, "%s\n", func_name);
		exit(0);
	}

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

