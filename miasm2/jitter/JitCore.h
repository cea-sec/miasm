#ifndef JITCORE_H
#define JITCORE_H

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
#define RAISE_ret0(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return 0;}


#define PyGetInt(item, value)						\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyInt_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		RAISE(PyExc_TypeError,"arg must be int");		\
	}								\


#define PyGetInt_retneg(item, value)					\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyInt_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		PyErr_SetString(PyExc_TypeError, "Arg must be int");	\
		return -1;						\
	}								\


#define getset_reg_bn(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		bn_t bn;						\
		PyObject* py_long;					\
		PyObject* py_tmp;					\
		PyObject* cst_32;					\
		uint64_t tmp;						\
		py_long = PyLong_FromLong(0);				\
		cst_32 = PyLong_FromLong(32);				\
		bn = ((vm_cpu_t*)(self->cpu))->  regname;		\
		while (!bignum_is_zero(bn)) {				\
			tmp = bignum_to_uint64(bignum_mask(bn, 32)) & 0xffffffff; \
			bn = bignum_rshift(bn, 32);			\
			py_tmp = PyLong_FromUnsignedLong(tmp);			\
			py_long = PyObject_CallMethod(py_long, "__lshift__", "O", cst_32); \
			py_long = PyObject_CallMethod(py_long, "__add__", "O", py_tmp);	\
		}							\
		return py_long;						\
	}								\
									\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		bn_t bn;						\
		int j;							\
		PyObject* py_long = value;				\
		PyObject* py_tmp;					\
		PyObject* cst_32;					\
		PyObject* cst_ffffffff;					\
		uint64_t tmp;						\
									\
		/* Ensure py_long is a PyLong */			\
		if (PyInt_Check(py_long)){				\
			tmp = (uint64_t)PyInt_AsLong(py_long);		\
			py_long = PyLong_FromLong(tmp);			\
		} else if (PyLong_Check(py_long)){			\
			/* Already PyLong */				\
		}							\
		else{							\
			PyErr_SetString(PyExc_TypeError, "Arg must be int"); \
			return -1;					\
		}							\
									\
		cst_ffffffff = PyLong_FromLong(0xffffffff);		\
		cst_32 = PyLong_FromLong(32);				\
		bn = bignum_from_int(0);				\
									\
		for (j = 0; j < BN_BYTE_SIZE; j += 4) {			\
			py_tmp = PyObject_CallMethod(py_long, "__and__", "O", cst_ffffffff); \
			tmp = PyLong_AsUnsignedLongMask(py_tmp);	\
			bn = bignum_lshift(bn, 32);			\
			bn = bignum_or(bn, bignum_from_uint64(tmp));	\
			py_long = PyObject_CallMethod(py_long, "__rshift__", "O", cst_32); \
		}							\
									\
		((vm_cpu_t*)(self->cpu))->  regname   = bn;		\
		return 0;						\
	}


#define getset_reg_u64(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint64_t)(((vm_cpu_t*)(self->cpu))->  regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint64_t val;						\
		PyGetInt_retneg(value, val);				\
		((vm_cpu_t*)(self->cpu))->  regname   = val;		\
		return 0;						\
	}

#define getset_reg_u32(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint32_t)(((vm_cpu_t*)(self->cpu))->  regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint32_t val;						\
		PyGetInt_retneg(value, val);				\
		((vm_cpu_t*)(self->cpu))->  regname   = val;		\
		return 0;						\
	}


#define getset_reg_u16(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint16_t)(((vm_cpu_t*)(self->cpu))-> regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint16_t val;						\
		PyGetInt_retneg(value, val);				\
		((vm_cpu_t*)(self->cpu))->  regname   = val;		\
		return 0;						\
	}


#define get_reg(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)((vm_cpu_t*)(self->cpu))->reg); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);


#define get_reg_bn(reg)  do {						\
		bn_t bn;						\
		PyObject* py_long;					\
		PyObject* py_tmp;					\
		PyObject* cst_32;					\
		uint64_t tmp;						\
		py_long = PyLong_FromLong(0);				\
		cst_32 = PyLong_FromLong(32);				\
		bn = ((vm_cpu_t*)(self->cpu))->  reg;			\
		while (!bignum_is_zero(bn)) {				\
			tmp = bignum_to_uint64(bignum_mask(bn, 32)) & 0xffffffff; \
			bn = bignum_rshift(bn, 32);			\
			py_tmp = PyLong_FromLong(tmp);			\
			py_long = PyObject_CallMethod(py_long, "__lshift__", "O", cst_32); \
			py_long = PyObject_CallMethod(py_long, "__add__", "O", py_tmp);	\
		}							\
		PyDict_SetItemString(dict, #reg, py_long);		\
		Py_DECREF(py_long);					\
	} while(0);


#define get_reg_off(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)offsetof(vm_cpu_t, reg)); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);




typedef struct {
	uint8_t is_local;
	uint64_t address;
} block_id;

typedef struct {
	PyObject_HEAD
	VmMngr *pyvm;
	PyObject *jitter;
	void* cpu;
} JitCpu;


typedef struct _reg_dict{
    char* name;
    size_t offset;
    size_t size;
} reg_dict;



void JitCpu_dealloc(JitCpu* self);
PyObject * JitCpu_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
PyObject * JitCpu_get_vmmngr(JitCpu *self, void *closure);
PyObject * JitCpu_set_vmmngr(JitCpu *self, PyObject *value, void *closure);
PyObject * JitCpu_get_jitter(JitCpu *self, void *closure);
PyObject * JitCpu_set_jitter(JitCpu *self, PyObject *value, void *closure);
void Resolve_dst(block_id* BlockDst, uint64_t addr, uint64_t is_local);

#define Resolve_dst(b, arg_addr, arg_is_local) do {(b)->address = (arg_addr); (b)->is_local = (arg_is_local);} while(0)



_MIASM_EXPORT uint8_t MEM_LOOKUP_08(JitCpu* jitcpu, uint64_t addr);
_MIASM_EXPORT uint16_t MEM_LOOKUP_16(JitCpu* jitcpu, uint64_t addr);
_MIASM_EXPORT uint32_t MEM_LOOKUP_32(JitCpu* jitcpu, uint64_t addr);
_MIASM_EXPORT uint64_t MEM_LOOKUP_64(JitCpu* jitcpu, uint64_t addr);

_MIASM_EXPORT bn_t MEM_LOOKUP_BN_BN(JitCpu* jitcpu, int size, bn_t addr);
_MIASM_EXPORT bn_t MEM_LOOKUP_INT_BN(JitCpu* jitcpu, int size, uint64_t addr);

_MIASM_EXPORT uint64_t MEM_LOOKUP_BN_INT(JitCpu* jitcpu, int size, bn_t addr);

_MIASM_EXPORT void MEM_WRITE_BN_BN(JitCpu* jitcpu, int size, bn_t addr, bn_t src);
_MIASM_EXPORT void MEM_WRITE_BN_INT(JitCpu* jitcpu, int size, bn_t addr, uint64_t src);
_MIASM_EXPORT void MEM_WRITE_INT_BN(JitCpu* jitcpu, int size, uint64_t addr, bn_t src);


PyObject* vm_get_mem(JitCpu *self, PyObject* args);

_MIASM_EXPORT void MEM_LOOKUP_INT_BN_TO_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr);
_MIASM_EXPORT void MEM_WRITE_INT_BN_FROM_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr);



#define VM_exception_flag (jitcpu->pyvm->vm_mngr.exception_flags)
#define CPU_exception_flag (((vm_cpu_t*)jitcpu->cpu)->exception_flags)
#define CPU_exception_flag_at_instr ((CPU_exception_flag) && ((CPU_exception_flag) > EXCEPT_NUM_UPDT_EIP))
#define JIT_RET_EXCEPTION 1
#define JIT_RET_NO_EXCEPTION 0

#endif
