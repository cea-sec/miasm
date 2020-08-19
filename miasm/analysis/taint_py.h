#ifndef TAINT_PY_H
#define TAINT_PY_H

#include "../jitter/interval_tree/interval_tree.h"

#define NB_BITS_IN_UINT32_T 32

#define DO_TAINT_REG_CB 1
#define DO_UNTAINT_REG_CB 1 << 1
#define DO_TAINT_MEM_CB 1 << 2
#define DO_UNTAINT_MEM_CB 1 << 3

# define DEFAULT_MAX_REG_SIZE 16
# define DEFAULT_REG_START 0

typedef struct {
    PyObject_HEAD
    struct taint_t *taint; // TODO: malloc in taint.c
} PyTaint;


PyObject* cpu_access_register(PyTaint* self, PyObject* args, uint32_t access_type);
PyObject* cpu_get_registers(struct rb_root ** registers,
			     uint64_t nb_registers,
			     uint32_t max_register_size
			     );
PyObject* cpu_taint_register(PyTaint* self, PyObject* args); // args: color_index(, register_index, start, end)
PyObject* cpu_untaint_register(PyTaint* self, PyObject* args); // args: color_index(, register_index, start, end)
PyObject* cpu_untaint_all_registers(PyTaint* self); // args: -
PyObject* cpu_color_untaint_all_registers(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_access_memory(PyTaint* self, PyObject* args, uint32_t access_type);
PyObject* cpu_taint_memory(PyTaint* self, PyObject* args); // args: addr, size, color_index
PyObject* cpu_untaint_memory(PyTaint* self, PyObject* args); // args: addr, size, color_index
PyObject* cpu_untaint_all_memory(PyTaint* self); // args: -
PyObject* cpu_color_untaint_all_memory(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_untaint_all(PyTaint* self); // args: -
PyObject* cpu_color_untaint_all(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_init_taint(PyTaint* self, PyObject* args); // args: nb_registers, nb_colors(, max_register_size)
PyObject* cpu_get_last_register(PyTaint* self, PyObject* args, uint32_t event_type);
PyObject* cpu_get_last_tainted_registers(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_get_last_untainted_registers(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_get_memory(struct rb_root * memory);
PyObject* cpu_get_last_memory(PyTaint* self, PyObject* args, uint32_t event_type);
PyObject* cpu_get_last_tainted_memory(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_get_last_untainted_memory(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_get_all_taint(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_enable_cb(PyTaint* self, PyObject* args, uint32_t cb);
PyObject* cpu_enable_taint_reg_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_enable_untaint_reg_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_enable_taint_mem_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_enable_untaint_mem_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_disable_cb(PyTaint* self, PyObject* args, uint32_t cb);
PyObject* cpu_disable_taint_reg_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_disable_untaint_reg_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_disable_taint_mem_cb(PyTaint* self, PyObject* args); // args: color_index
PyObject* cpu_disable_untaint_mem_cb(PyTaint* self, PyObject* args); // args: color_index
#endif
