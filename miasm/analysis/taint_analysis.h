#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

#define DO_RAISE_EXCEPTION 1
#define NB_BITS_IN_UINT32_T 32
#define NB_MEM_ALLOC_CB 8

#define EXCEPT_TAINT (1 << 4)
#define EXCEPT_TAINT_ADD_REG ((1 << 14) | EXCEPT_TAINT)
#define EXCEPT_TAINT_REMOVE_REG ((1 << 15) | EXCEPT_TAINT)
#define EXCEPT_TAINT_ADD_MEM ((1 << 16) | EXCEPT_TAINT)
#define EXCEPT_TAINT_REMOVE_MEM ((1 << 17) | EXCEPT_TAINT)

#define DO_TAINT_REG_CB 1
#define DO_UNTAINT_REG_CB 1 << 1
#define DO_TAINT_MEM_CB 1 << 2
#define DO_UNTAINT_MEM_CB 1 << 3

#define ADD 1
#define REMOVE 2

#define TAINT_EVENT 1
#define UNTAINT_EVENT 2

# define DEFAULT_MAX_REG_SIZE 8
# define DEFAULT_REG_START 0

#define TAINT_METHODS {"taint_register", (PyCFunction)cpu_taint_register, METH_VARARGS, \
	 "X"}, \
	{"untaint_register", (PyCFunction)cpu_untaint_register, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_registers_of_color", (PyCFunction)cpu_color_untaint_all_registers, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_registers", (PyCFunction)cpu_untaint_all_registers, METH_NOARGS, \
	 "X"}, \
	{"taint_memory", (PyCFunction)cpu_taint_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_memory", (PyCFunction)cpu_untaint_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_memory_of_color", (PyCFunction)cpu_color_untaint_all_memory, METH_VARARGS, \
	 "X"}, \
	{"untaint_all_memory", (PyCFunction)cpu_untaint_all_memory, METH_NOARGS, \
	 "X"}, \
	{"untaint_all_of_color", (PyCFunction)cpu_color_untaint_all, METH_VARARGS, \
	 "X"}, \
	{"untaint_all", (PyCFunction)cpu_untaint_all, METH_NOARGS, \
	 "X"}, \
	{"init_taint_analysis", (PyCFunction)cpu_init_taint, METH_VARARGS, \
	 "X"}, \
	{"last_tainted_registers", (PyCFunction)cpu_get_last_tainted_registers, METH_VARARGS, \
	 "X"}, \
	{"last_untainted_registers", (PyCFunction)cpu_get_last_untainted_registers, METH_VARARGS, \
	 "X"}, \
	{"last_tainted_memory", (PyCFunction)cpu_get_last_tainted_memory, METH_VARARGS, \
	 "X"}, \
	{"last_untainted_memory", (PyCFunction)cpu_get_last_untainted_memory, METH_VARARGS, \
	 "X"}, \
	{"get_all_taint", (PyCFunction)cpu_get_all_taint, METH_VARARGS, \
	 "X"}, \
	{"enable_taint_reg_cb", (PyCFunction)cpu_enable_taint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_untaint_reg_cb", (PyCFunction)cpu_enable_untaint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_taint_mem_cb", (PyCFunction)cpu_enable_taint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"enable_untaint_mem_cb", (PyCFunction)cpu_enable_untaint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_taint_reg_cb", (PyCFunction)cpu_disable_taint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_untaint_reg_cb", (PyCFunction)cpu_disable_untaint_reg_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_taint_mem_cb", (PyCFunction)cpu_disable_taint_mem_cb, METH_VARARGS, \
	 "X"}, \
	{"disable_untaint_mem_cb", (PyCFunction)cpu_disable_untaint_mem_cb, METH_VARARGS, \
	 "X"}, \

struct taint_interval_t {
	uint64_t start;
	uint64_t end;
};

struct taint_last_modify_t {
	struct rb_root **registers;
	struct rb_root *memory;
};

struct taint_callback_info_t {
	struct taint_last_modify_t last_tainted;
	struct taint_last_modify_t last_untainted;

	// Callback flags
	// Added in order to do callbacks
	// only when needed (optimisation purposes).
	uint32_t exception_flag;
};

struct taint_color_t {
	struct rb_root **registers;
	struct rb_root *memory;
	struct taint_callback_info_t *callback_info;
};

struct taint_colors_t {
	struct taint_color_t *colors;
	uint64_t nb_colors;
	uint64_t nb_registers;
	uint32_t max_register_size;
};

// WIP
struct taint_reg_list_t {
	uint64_t id;
    struct taint_interval_t *interval;
    struct taint_custom_list_t *next;
};

// WIP
struct taint_mem_list_t {
	uint64_t addr;
    struct taint_interval_t *interval;
    struct taint_custom_list_t *next;
};

// WIP
struct rb_root* taint_get_tainted(struct taint_colors_t *colors,
				                  uint64_t color_index,
                                  struct taint_reg_list_t *registers,
                                  struct taint_reg_list_t *reg_addresses,
                                  struct taint_mem_list_t *mem_addresses,
                                  struct taint_custom_list_t *memories
                                  );

/* Colors */
struct taint_colors_t* taint_init_colors(uint64_t nb_regs,
					 uint64_t nb_registers,
					 uint32_t max_register_size
					 );
struct taint_color_t taint_init_color(uint64_t nb_regs, uint32_t max_register_size);
void taint_check_color(uint64_t color_index, uint64_t nb_colors);
void taint_check_register(uint64_t register_index,
			  struct taint_interval_t* interval,
			  uint64_t nb_registers,
			  uint32_t max_register_size
			  );

/* Registers */
_MIASM_EXPORT void taint_register_generic_access(struct taint_colors_t *colors,
				   uint64_t color_index,
				   uint64_t register_index,
				   struct taint_interval_t* interval,
				   uint32_t access_type
				   );
_MIASM_EXPORT struct rb_root * taint_get_register_color(struct taint_colors_t *colors,
						    uint64_t color_index,
						    uint64_t register_index,
						    struct taint_interval_t* interval
						    );
struct rb_root * taint_get_register(struct rb_root ** registers,
					      uint64_t register_index,
					      struct taint_interval_t* interval,
					      uint32_t max_register_size
					      );
void taint_color_init_registers(struct taint_color_t *color, uint64_t nb_registers);
void taint_remove_all_registers(struct taint_colors_t *colors);
void taint_color_remove_all_registers(struct taint_colors_t *colors,
				      uint64_t color_index
				      );

/* Memory */
_MIASM_EXPORT void taint_memory_generic_access(struct taint_colors_t *colors,
                 uint64_t color_index,
                 struct taint_interval_t* interval,
				 uint32_t access_type
				 );
_MIASM_EXPORT struct rb_root * taint_get_memory(struct taint_colors_t *colors,
					    uint64_t color_index,
                        struct taint_interval_t* interval
                        );
void taint_remove_all_memory(struct taint_colors_t *colors);
void taint_color_remove_all_memory(struct taint_colors_t *colors, uint64_t color_index);
void taint_color_init_memory(struct taint_color_t *color);

/* Callback information */
struct taint_callback_info_t *taint_init_callback_info(uint64_t nb_registers,
						       uint32_t max_register_size
						       );
_MIASM_EXPORT void taint_clean_all_callback_info(struct taint_colors_t *colors);
void taint_clean_callback_info(struct taint_colors_t *colors,
			       uint64_t color_index
			       );
_MIASM_EXPORT void taint_update_register_callback_info(struct taint_colors_t *colors,
					 uint64_t color_index,
					 uint64_t register_index,
					 struct taint_interval_t* interval,
					 int event_type
					 );
_MIASM_EXPORT void taint_update_memory_callback_info(struct taint_colors_t *colors,
				       uint64_t color_index,
					   struct taint_interval_t* interval,
				       int event_type
				       );

/* Python API */
PyObject* cpu_access_register(JitCpu* cpu, PyObject* args, uint32_t access_type);
PyObject* cpu_get_registers(struct rb_root ** registers,
			     uint64_t nb_registers,
			     uint32_t max_register_size
			     );
PyObject* cpu_taint_register(JitCpu* self, PyObject* args); // args: color_index(, register_index, start, end)
PyObject* cpu_untaint_register(JitCpu* self, PyObject* args); // args: color_index(, register_index, start, end)
PyObject* cpu_untaint_all_registers(JitCpu* self); // args: -
PyObject* cpu_color_untaint_all_registers(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_access_memory(JitCpu* cpu, PyObject* args, uint32_t access_type);
PyObject* cpu_taint_memory(JitCpu* self, PyObject* args); // args: addr, size, color_index
PyObject* cpu_untaint_memory(JitCpu* self, PyObject* args); // args: addr, size, color_index
PyObject* cpu_untaint_all_memory(JitCpu* self); // args: -
PyObject* cpu_color_untaint_all_memory(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_untaint_all(JitCpu* self); // args: -
PyObject* cpu_color_untaint_all(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_init_taint(JitCpu* self, PyObject* args); // args: nb_registers, nb_colors(, max_register_size)
PyObject* cpu_get_last_register(JitCpu* cpu, PyObject* args, uint32_t event_type);
PyObject* cpu_get_last_tainted_registers(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_get_last_untainted_registers(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_get_memory(struct rb_root * memory);
PyObject* cpu_get_last_memory(JitCpu* cpu, PyObject* args, uint32_t event_type);
PyObject* cpu_get_last_tainted_memory(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_get_last_untainted_memory(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_get_all_taint(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_enable_cb(JitCpu* cpu, PyObject* args, uint32_t cb);
PyObject* cpu_enable_taint_reg_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_enable_untaint_reg_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_enable_taint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_enable_untaint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_disable_cb(JitCpu* cpu, PyObject* args, uint32_t cb);
PyObject* cpu_disable_taint_reg_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_disable_untaint_reg_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_disable_taint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject* cpu_disable_untaint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
