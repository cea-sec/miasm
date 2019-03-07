#ifndef VM_MNGR_PY_H
#define VM_MNGR_PY_H

#ifdef _WIN32
#define SIGALRM 0
#endif

typedef struct {
	PyObject_HEAD
	PyObject *vmmngr;
	vm_mngr_t vm_mngr;
} VmMngr;


#endif// VM_MNGR_PY_H
