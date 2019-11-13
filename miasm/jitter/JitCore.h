#ifndef JITCORE_H
#define JITCORE_H

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)

#ifndef SSIZE_MAX
#ifdef _WIN64
#define SSIZE_MAX _I64_MAX
#else
#define SSIZE_MAX INT_MAX
#endif
#endif

#else
#define _MIASM_EXPORT
#endif

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
#define RAISE_ret0(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return 0;}


#if PY_MAJOR_VERSION >= 3
#define getset_reg_bn(regname, size)					\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		bn_t bn;						\
		PyObject* py_long;					\
		bn = (self->cpu)->regname;				\
		bn = bignum_mask(bn, (size));				\
		py_long = bn_to_PyLong(bn);				\
		return py_long;						\
	}								\
									\
	static PyObject *JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		bn_t bn;						\
		PyObject* py_long = value;				\
		if (PyLong_Check(py_long)){				\
				Py_INCREF(py_long);			\
			} else {					\
				RAISE(PyExc_TypeError,"arg must be int"); \
			}						\
									\
		bn = PyLong_to_bn(py_long);				\
									\
		(self->cpu)->regname = bignum_mask(bn, (size));		\
		return 0;						\
	}


#else
#define getset_reg_bn(regname, size)					\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		bn_t bn;						\
		PyObject* py_long;					\
		bn = (self->cpu)->regname;				\
		bn = bignum_mask(bn, (size));				\
		py_long = bn_to_PyLong(bn);				\
		return py_long;						\
	}								\
									\
	static PyObject *JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		bn_t bn;						\
		PyObject* py_long = value;				\
		uint64_t tmp;						\
									\
		if (PyInt_Check(py_long)){				\
			tmp = (uint64_t)PyInt_AsLong(py_long);		\
			py_long = PyLong_FromLong((long)tmp);		\
		} else if (PyLong_Check(py_long)){			\
			Py_INCREF(py_long);				\
		}							\
		else{							\
			RAISE(PyExc_TypeError,"arg must be int");	\
		}							\
									\
		bn = PyLong_to_bn(py_long);				\
									\
		self->cpu->regname = bignum_mask(bn, (size));		\
		return 0;						\
	}
#endif











#define getset_reg_u64(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong(self->cpu->regname); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint64_t val;						\
		PyGetInt_uint64_t_retneg(value, val);			\
		self->cpu->regname = val;				\
		return 0;						\
	}

#define getset_reg_u32(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong(self->cpu->regname); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint32_t val;						\
		PyGetInt_uint32_t_retneg(value, val);			\
		self->cpu->regname = val;				\
		return 0;						\
	}


#define getset_reg_u16(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong(self->cpu->regname); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint16_t val;						\
		PyGetInt_uint16_t_retneg(value, val);			\
		self->cpu->regname = val;				\
		return 0;						\
	}


#define getset_reg_u8(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong(self->cpu->regname); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint8_t val;						\
		PyGetInt_uint8_t_retneg(value, val);			\
		self->cpu->regname = val;				\
		return 0;						\
	}


#define get_reg(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)self->cpu->reg); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);


#define get_reg_bn(reg, size)  do {					\
		bn_t bn;						\
		PyObject* py_long;					\
		bn = self->cpu->reg;					\
		bn = bignum_mask(bn, size);				\
		py_long = bn_to_PyLong(bn);				\
		PyDict_SetItemString(dict, #reg, py_long);		\
		Py_DECREF(py_long);					\
	} while(0);


#define get_reg_off(reg)  do {						\
		o = PyLong_FromUnsignedLongLong((uint64_t)offsetof(struct vm_cpu, reg)); \
		PyDict_SetItemString(dict, #reg, o);			\
		Py_DECREF(o);						\
	} while(0);




typedef struct {
	uint8_t is_local;
	uint64_t address;
} block_id;

struct vm_cpu;

typedef struct {
	PyObject_HEAD
	VmMngr *pyvm;
	PyObject *jitter;
	struct vm_cpu *cpu;
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
PyObject * JitCpu_get_vmcpu(JitCpu *self, void *closure);
PyObject * JitCpu_set_vmcpu(JitCpu *self, PyObject *value, void *closure);
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


_MIASM_EXPORT void MEM_LOOKUP_INT_BN_TO_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr);
_MIASM_EXPORT void MEM_WRITE_INT_BN_FROM_PTR(JitCpu* jitcpu, int size, uint64_t addr, char* ptr);



#define VM_exception_flag (jitcpu->pyvm->vm_mngr.exception_flags)
#define CPU_exception_flag (((struct vm_cpu*)jitcpu->cpu)->exception_flags)
#define CPU_exception_flag_at_instr ((CPU_exception_flag) && ((CPU_exception_flag) > EXCEPT_NUM_UPDT_EIP))
#define JIT_RET_EXCEPTION 1
#define JIT_RET_NO_EXCEPTION 0

#endif
