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

#define BIT_FIELD_SIZE(nb_elements) (nb_elements/NB_BITS_IN_UINT32_T + 1)

# define DEFAULT_MAX_REG_SIZE 8
# define DEFAULT_REG_START 0

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct taint_interval_t {
	uint32_t start;
	uint32_t end;
};

struct taint_memory_cb_t {
	uint64_t addr;
	uint64_t size;
};

struct taint_last_modify_t {
	// Register info
	uint32_t *registers;

	// Memory info
	uint64_t nb_mem;
	uint64_t allocated;
	struct taint_memory_cb_t *memory;
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
	uint32_t *registers;
	struct taint_callback_info_t *callback_info;
};

struct taint_colors_t {
	struct taint_color_t *colors;
	uint64_t nb_colors;
	uint64_t nb_registers;
	uint32_t max_register_size;
};

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

/* Regsiters */
void taint_register_generic_access(struct taint_colors_t *colors,
				   uint64_t color_index,
				   uint64_t register_index,
				   struct taint_interval_t* interval,
				   uint32_t access_type
				   );
struct taint_interval_t* taint_get_register_color(struct taint_colors_t *colors,
						    uint64_t color_index,
						    uint64_t register_index,
						    struct taint_interval_t* interval
						    );
struct taint_interval_t* taint_get_register(uint32_t* registers,
					      uint64_t register_index,
					      struct taint_interval_t* interval,
					      uint32_t max_register_size
					      );
void taint_remove_all_registers(struct taint_colors_t *colors);
void taint_color_remove_all_registers(struct taint_colors_t *colors,
				      uint64_t color_index
				      );

/* Memory */
void taint_memory_generic_access(vm_mngr_t* vm_mngr,
				 uint64_t addr,
				 uint64_t size,
				 uint32_t access_type,
				 uint64_t color_index
				 );
struct taint_interval_t* taint_get_memory(vm_mngr_t* vm_mngr,
					    uint64_t addr,
					    uint64_t size,
					    uint64_t color_index
					    );
void taint_remove_all_memory(vm_mngr_t* vm_mngr);
void taint_color_remove_all_memory(vm_mngr_t* vm_mngr, uint64_t color_index);
void taint_init_memory(vm_mngr_t* vm_mngr, uint64_t color_index);

/* Callback information */
struct taint_callback_info_t *taint_init_callback_info(uint64_t nb_registers,
						       uint32_t max_register_size
						       );
void taint_clean_all_callback_info(struct taint_colors_t *colors);
void taint_clean_callback_info(struct taint_colors_t *colors,
			       uint64_t color_index
			       );
void taint_update_register_callback_info(struct taint_colors_t *colors,
					 uint64_t color_index,
					 uint64_t register_index,
					 struct taint_interval_t* interval,
					 int event_type
					 );
void taint_update_memory_callback_info(struct taint_colors_t *colors,
				       uint64_t color_index,
				       uint64_t addr,
				       uint64_t size,
				       int event_type
				       );

/* Utils */
void bitfield_set_bit(uint32_t bfield[],  uint64_t index);
void bitfield_unset_bit(uint32_t bfield[],  uint64_t index);
void bitfield_generic_access(uint32_t bitfield[],
			     uint64_t index,
			     uint32_t access_type
			     );
int bitfield_test_bit(uint32_t bfield[],  uint64_t index);

/* Python API */
PyObject* cpu_access_register(JitCpu* cpu, PyObject* args, uint32_t access_type);
PyObject* cpu_get_registers(uint32_t* registers,
			     uint64_t nb_registers,
			     uint32_t max_register_size
			     );
PyObject* cpu_taint_register(JitCpu* self, PyObject* args); // args: color_index(, register_index, start, size)
PyObject* cpu_untaint_register(JitCpu* self, PyObject* args); // args: color_index(, register_index, start, size)
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
PyObject* cpu_get_memory(vm_mngr_t* vm_mngr, uint64_t color_index);
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
