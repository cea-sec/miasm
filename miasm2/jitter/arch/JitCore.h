
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


#define PyGetInt_ret0(item, value)					\
	if (PyInt_Check(item)){						\
		value = (uint64_t)PyInt_AsLong(item);			\
	}								\
	else if (PyLong_Check(item)){					\
		value = (uint64_t)PyLong_AsUnsignedLongLong(item);	\
	}								\
	else{								\
		printf("error\n"); return 0;				\
	}								\



#define getset_reg_u64(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint64_t)(self->vmcpu.  regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint64_t val;						\
		PyGetInt_ret0(value, val);				\
		self->vmcpu.  regname   = val;				\
		return 0;						\
	}

#define getset_reg_u32(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint32_t)(self->vmcpu.  regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint32_t val;						\
		PyGetInt_ret0(value, val);				\
		self->vmcpu.  regname   = val;				\
		return 0;						\
	}


#define getset_reg_u16(regname)						\
	static PyObject *JitCpu_get_ ## regname  (JitCpu *self, void *closure) \
	{								\
		return PyLong_FromUnsignedLongLong((uint16_t)(self->vmcpu.  regname  )); \
	}								\
	static int JitCpu_set_ ## regname  (JitCpu *self, PyObject *value, void *closure) \
	{								\
		uint16_t val;						\
		PyGetInt_ret0(value, val);				\
		self->vmcpu.  regname   = val;				\
		return 0;						\
	}


typedef struct {
	uint8_t is_local;
	uint64_t address;
} block_id;

block_id Resolve_dst(uint64_t addr, uint64_t is_local);
