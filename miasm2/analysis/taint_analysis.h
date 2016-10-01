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

#define ADD_MEMORY 1
#define REMOVE_MEMORY 2
#define TEST_MEMORY 3

struct taint_memory_cb_t {
	uint64_t addr;
	uint64_t size;
};

struct taint_callback_info_t {
	// Register info
	uint32_t *registers;

	// Memory info
	uint64_t nb_mem;
	uint64_t allocated;
	struct taint_memory_cb_t *memory;

	// Callback flags
	// Added in order to do callbacks
	// only when needed (optimisation purposes).
	uint32_t exception_flag;
	// TODO: add on_taint and on_untaint
	// Indeed, one operation can taint and untaint
	// at the same time (ex: PUSHAD)
	// TODO: add source of taint/untaint
	// need to:
	//      - have one holder for taint one for untaint
	//      - can it be several registers or register and
	//      memory ?
	//              -> yes PUSHAD for several register and
	//              mov ebx, [EAX] if EAX and [EAX] are tainted
	//              they both are sources

};

struct taint_color_t {
	uint32_t *registers;
	struct taint_callback_info_t *callback_info;
};

struct taint_colors_t {
	struct taint_color_t *colors;
	uint64_t nb_colors;
	uint64_t nb_registers;
};

/* Colors */
struct taint_color_t taint_init_color(uint64_t nb_regs);
void taint_check_color(uint64_t color_index, uint64_t nb_colors);
void taint_add_callback_register(struct taint_colors_t *colors,
			uint64_t color_index,
			uint64_t register_index
			);

/* Regsiters */
void taint_add_register(struct taint_colors_t *colors,
			uint64_t color_index,
			uint64_t register_index
			);
void taint_remove_register(struct taint_colors_t *colors,
			   uint64_t color_index,
			   uint64_t register_index
			   );
int taint_get_register(struct taint_colors_t *colors,
		       uint64_t color_index,
		       uint64_t register_index
		       );
void taint_remove_all_registers(struct taint_colors_t *colors,
				uint64_t color_index
				);

/* Memory */
int taint_generic_access(vm_mngr_t* vm_mngr,
			 uint64_t addr,
			 uint64_t size,
			 int access_type,
			 uint64_t color_index
			 );
int taint_action_on_access(uint32_t *taint, uint64_t index, int access_type);
void taint_add_memory(vm_mngr_t* vm_mngr,
		      uint64_t addr,
		      uint64_t size,
		      uint64_t color_index
		      );
void taint_remove_memory(vm_mngr_t* vm_mngr,
			 uint64_t addr,
			 uint64_t size,
			 uint64_t color_index
			 );
int taint_get_memory(vm_mngr_t* vm_mngr,
		     uint64_t addr,
		     uint64_t size,
		     uint64_t color_index
		     );
void taint_remove_all_memory(vm_mngr_t* vm_mngr);
void taint_init_memory(vm_mngr_t* vm_mngr, uint64_t color_index);

/* Callback information */
struct taint_callback_info_t *taint_init_callback_info(uint64_t nb_registers);
void taint_clean_all_callback_info(struct taint_colors_t *colors);
void taint_clean_callback_info_unsafe(struct taint_colors_t *colors,
				      uint64_t color_index
				      );
void taint_clean_callback_info_safe(struct taint_colors_t *colors,
				    uint64_t color_index
				    );
void taint_update_memory_callback_info(struct taint_colors_t *colors,
				       uint64_t color_index,
				       uint64_t addr,
				       uint64_t size
				       );

/* Utils */
void bitfield_set_bit(uint32_t bfield[],  uint64_t index);
void bitfield_unset_bit(uint32_t bfield[],  uint64_t index);
int bitfield_test_bit(uint32_t bfield[],  uint64_t index);

/* Python API */
PyObject *cpu_taint_register(JitCpu* self, PyObject* args); // args: color_index, register_index
PyObject *cpu_untaint_register(JitCpu* self, PyObject* args); // args: color_index, register_index
PyObject *cpu_untaint_all_registers(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_taint_memory(JitCpu* self, PyObject* args); // args: addr, size, color_index
PyObject *cpu_untaint_memory(JitCpu* self, PyObject* args); // args: addr, size, color_index
PyObject *cpu_untaint_all_memory(JitCpu* self); // args: -
PyObject *cpu_untaint_all(JitCpu* self); // args: -
PyObject *cpu_init_taint(JitCpu* self, PyObject* args); // args: nb_registers, nb_colors
PyObject *cpu_get_last_tainted_registers(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_get_last_tainted_memory(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_get_all_taint(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_do_taint_reg_cb(JitCpu* self, PyObject* args); // args: color_inde
PyObject *cpu_do_untaint_reg_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_do_taint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
PyObject *cpu_do_untaint_mem_cb(JitCpu* self, PyObject* args); // args: color_index
