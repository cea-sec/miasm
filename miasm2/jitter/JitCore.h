#ifndef JITCORE_H
#define JITCORE_H

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
} reg_dict;



void JitCpu_dealloc(JitCpu* self);
PyObject * JitCpu_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
PyObject * JitCpu_get_vmmngr(JitCpu *self, void *closure);
PyObject * JitCpu_set_vmmngr(JitCpu *self, PyObject *value, void *closure);
PyObject * JitCpu_get_jitter(JitCpu *self, void *closure);
PyObject * JitCpu_set_jitter(JitCpu *self, PyObject *value, void *closure);
void Resolve_dst(block_id* BlockDst, uint64_t addr, uint64_t is_local);

#define Resolve_dst(b, arg_addr, arg_is_local) do {(b)->address = (arg_addr); (b)->is_local = (arg_is_local);} while(0)



uint8_t MEM_LOOKUP_08(JitCpu* jitcpu, uint64_t addr);
uint16_t MEM_LOOKUP_16(JitCpu* jitcpu, uint64_t addr);
uint32_t MEM_LOOKUP_32(JitCpu* jitcpu, uint64_t addr);
uint64_t MEM_LOOKUP_64(JitCpu* jitcpu, uint64_t addr);
void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);
PyObject* vm_get_mem(JitCpu *self, PyObject* args);



#define VM_exception_flag (jitcpu->pyvm->vm_mngr.exception_flags)
#define CPU_exception_flag (((vm_cpu_t*)jitcpu->cpu)->exception_flags)
#define CPU_exception_flag_at_instr ((CPU_exception_flag) && ((CPU_exception_flag) > EXCEPT_NUM_UPDT_EIP))
#define JIT_RET_EXCEPTION 1
#define JIT_RET_NO_EXCEPTION 0

#endif
