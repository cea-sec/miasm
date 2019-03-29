#ifndef __COMPAT_PY23_H__
#define __COMPAT_PY23_H__

#if PY_MAJOR_VERSION >= 3
#include "bn.h"
#define PyGetInt_uint_t(size_type, item, value)				\
	if (PyLong_Check(item)) {					\
		bn_t bn;						\
		int j;							\
		PyObject* py_long = item;				\
		PyObject* py_long_new;					\
		PyObject* py_tmp;					\
		PyObject* cst_32;					\
		PyObject* cst_ffffffff;					\
		uint64_t tmp;						\
		cst_ffffffff = PyLong_FromLong(0xffffffff);		\
		cst_32 = PyLong_FromLong(32);				\
		bn = bignum_from_int(0);				\
		int neg = 0;    					\
									\
		if (Py_SIZE(py_long) < 0) {				\
			neg = 1;					\
			py_long_new = PyObject_CallMethod(py_long, "__neg__", NULL); \
			Py_DECREF(py_long);				\
			py_long = py_long_new;				\
		}							\
									\
		for (j = 0; j < BN_BYTE_SIZE; j += 4) {			\
			py_tmp = PyObject_CallMethod(py_long, "__and__", "O", cst_ffffffff); \
			py_long_new = PyObject_CallMethod(py_long, "__rshift__", "O", cst_32); \
			Py_DECREF(py_long);				\
			py_long = py_long_new;				\
			tmp = PyLong_AsUnsignedLongLongMask(py_tmp);	\
			Py_DECREF(py_tmp);				\
			bn = bignum_or(bn, bignum_lshift(bignum_from_uint64(tmp), 8 * j)); \
		}							\
		tmp = bignum_to_uint64(bn);				\
									\
		if (neg) {						\
			if ( tmp > (size_type) -1) {                \
				RAISE(PyExc_TypeError, "Arg too big for " #size_type ""); \
			} 						\
			tmp = (1<<(sizeof(size_type)*8))-tmp; 		\
		}							\
		else if ( tmp > (size_type) -1) {                       \
			RAISE(PyExc_TypeError, "Arg too big for " #size_type ""); \
		}							\
		value = (size_type) tmp;				\
	}								\
	else{								\
		RAISE(PyExc_TypeError, "Arg must be int");		\
	}


#define PyGetInt_uint_t_retneg(size_type, item, value)			\
	if (PyLong_Check(item)) {					\
		bn_t bn;						\
		int j;							\
		PyObject* py_long = item;				\
		PyObject* py_long_new;					\
		PyObject* py_tmp;					\
		PyObject* cst_32;					\
		PyObject* cst_ffffffff;					\
		uint64_t tmp;						\
		cst_ffffffff = PyLong_FromLong(0xffffffff);		\
		cst_32 = PyLong_FromLong(32);				\
		bn = bignum_from_int(0);				\
		int neg = 0;    					\
									\
		if (Py_SIZE(py_long) < 0) {				\
			neg = 1;					\
			py_long_new = PyObject_CallMethod(py_long, "__neg__", NULL); \
			Py_DECREF(py_long);				\
			py_long = py_long_new;				\
		}							\
									\
		for (j = 0; j < BN_BYTE_SIZE; j += 4) {			\
			py_tmp = PyObject_CallMethod(py_long, "__and__", "O", cst_ffffffff); \
			py_long_new = PyObject_CallMethod(py_long, "__rshift__", "O", cst_32); \
			Py_DECREF(py_long);				\
			py_long = py_long_new;				\
			tmp = PyLong_AsUnsignedLongLongMask(py_tmp);	\
			Py_DECREF(py_tmp);				\
			bn = bignum_or(bn, bignum_lshift(bignum_from_uint64(tmp), 8 * j)); \
		}							\
		tmp = bignum_to_uint64(bn);				\
									\
		if (neg) {						\
			if ( tmp > (size_type) -1) {                \
				PyErr_SetString(PyExc_TypeError, "Arg too big for " #size_type ""); \
				return -1; 				\
			} 						\
			tmp = (1<<(sizeof(size_type)*8))-tmp; 		\
		}							\
		else if ( tmp > (size_type) -1) {                       \
			PyErr_SetString(PyExc_TypeError, "Arg too big for " #size_type ""); \
			return -1; 					\
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
