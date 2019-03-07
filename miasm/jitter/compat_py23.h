#ifndef __COMPAT_PY23_H__
#define __COMPAT_PY23_H__



#if PY_MAJOR_VERSION >= 3
#define PyGetInt(item, value)						\
	if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		RAISE(PyExc_TypeError,"arg must be int");		\
	}


#define PyGetInt_retneg(item, value)					\
	if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		PyErr_SetString(PyExc_TypeError, "Arg must be int");	\
		return -1;						\
	}

#define PyGetStr(dest, name)						\
	if (!PyUnicode_Check((name)))					\
		RAISE(PyExc_TypeError,"Page name must be bytes");	\
	(dest) = PyUnicode_AsUTF8((name))



#else
#define PyGetInt(item, value)						\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyInt_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		RAISE(PyExc_TypeError,"arg must be int");		\
	}


#define PyGetInt_retneg(item, value)					\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyLong_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		PyErr_SetString(PyExc_TypeError, "Arg must be int");	\
		return -1;						\
	}								\


#define PyGetStr(dest, name)						\
	if (!PyString_Check((name)))					\
		RAISE(PyExc_TypeError,"Page name must be bytes");	\
	(dest) = PyString_AsString((name))

#endif



#if PY_MAJOR_VERSION >= 3

#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define MOD_DEF(ob, name, doc, methods)		  \
	static struct PyModuleDef moduledef = {				\
					       PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
	ob = PyModule_Create(&moduledef);
#else

#define MOD_INIT(name) PyMODINIT_FUNC init##name(void)

#define MOD_DEF(ob, name, doc, methods)			\
	ob = Py_InitModule3(name, methods, doc);
#endif





#endif
