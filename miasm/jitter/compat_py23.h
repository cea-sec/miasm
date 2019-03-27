#ifndef __COMPAT_PY23_H__
#define __COMPAT_PY23_H__



#if PY_MAJOR_VERSION >= 3
#define PyGetInt_uint_t(size_type, item, value)				\
	if (PyLong_Check(item)) {					\
		unsigned long long tmp;					\
		tmp = PyLong_AsUnsignedLongLong(item);			\
		if ( tmp > (size_type) -1) {				\
			RAISE(PyExc_TypeError, "Arg too big for " #size_type ""); \
		}							\
		value = (size_type) tmp;				\
	}								\
	else{								\
		RAISE(PyExc_TypeError, "Arg must be int");		\
	}


#define PyGetInt_uint_t_retneg(size_type, item, value)			\
	if (PyLong_Check(item)) {					\
		unsigned long long tmp;					\
		tmp = PyLong_AsUnsignedLongLong(item);			\
		if ( tmp > (size_type) -1) {				\
			PyErr_SetString(PyExc_TypeError, "Arg too big for " #size_type ""); \
			return -1;					\
		}							\
		value = (size_type) tmp;				\
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
#define PyGetInt_uint_t(size_type, item, value)				\
	if (PyInt_Check(item)) {					\
		long tmp;						\
		tmp = PyInt_AsLong(item);				\
		if ( tmp > (size_type) -1) {				\
			RAISE(PyExc_TypeError, "Arg too big for " #size_type ""); \
		}							\
		value = (size_type) tmp;				\
	}								\
	else if (PyLong_Check(item)){					\
		unsigned long long tmp;					\
		tmp = PyLong_AsUnsignedLongLong(item);			\
		if ( tmp > (size_type) -1) {				\
			RAISE(PyExc_TypeError, "Arg too big for " #size_type ""); \
		}							\
		value = (size_type) tmp;				\
	}								\
	else{								\
		RAISE(PyExc_TypeError, "Arg must be int");		\
	}


#define PyGetInt_uint_t_retneg(size_type, item, value)			\
	if (PyInt_Check(item)) {					\
		long tmp;						\
		tmp = PyLong_AsLong(item);				\
		if ( tmp > (size_type) -1) {				\
			PyErr_SetString(PyExc_TypeError, "Arg too big for " #size_type ""); \
			return -1;					\
		}							\
		value = (size_type) tmp;				\
	}								\
	else if (PyLong_Check(item)){					\
		unsigned long long tmp;					\
		tmp = PyLong_AsUnsignedLongLong(item);			\
		if ( tmp > (size_type) -1) {				\
			PyErr_SetString(PyExc_TypeError, "Arg too big for " #size_type ""); \
			return -1;					\
		}							\
		value = (size_type) tmp;				\
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



#define PyGetInt_size_t(item, value) PyGetInt_uint_t(size_t, item, value)

#define PyGetInt_uint8_t(item, value) PyGetInt_uint_t(uint8_t, item, value)
#define PyGetInt_uint16_t(item, value) PyGetInt_uint_t(uint16_t, item, value)
#define PyGetInt_uint32_t(item, value) PyGetInt_uint_t(uint32_t, item, value)
#define PyGetInt_uint64_t(item, value) PyGetInt_uint_t(uint64_t, item, value)

#define PyGetInt_uint8_t_retneg(item, value) PyGetInt_uint_t_retneg(uint8_t, item, value)
#define PyGetInt_uint16_t_retneg(item, value) PyGetInt_uint_t_retneg(uint16_t, item, value)
#define PyGetInt_uint32_t_retneg(item, value) PyGetInt_uint_t_retneg(uint32_t, item, value)
#define PyGetInt_uint64_t_retneg(item, value) PyGetInt_uint_t_retneg(uint64_t, item, value)



#if PY_MAJOR_VERSION >= 3

#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define MOD_DEF(ob, name, doc, methods)		  \
	static struct PyModuleDef moduledef = {				\
					       PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
	ob = PyModule_Create(&moduledef);
#define RET_MODULE return module

#else

#define MOD_INIT(name) PyMODINIT_FUNC init##name(void)

#define MOD_DEF(ob, name, doc, methods)			\
	ob = Py_InitModule3(name, methods, doc);

#define RET_MODULE return
#endif





#endif
