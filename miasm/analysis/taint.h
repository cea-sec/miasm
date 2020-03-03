#ifndef TAINT_H 
#define TAINT_H 

#include "../jitter/interval_tree/interval_tree.h"

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

#define DO_RAISE_EXCEPTION 1
#define NB_MEM_ALLOC_CB 8

#define EXCEPT_TAINT (1 << 4)
#define EXCEPT_TAINT_REG ((1 << 14) | EXCEPT_TAINT)
#define EXCEPT_UNTAINT_REG ((1 << 15) | EXCEPT_TAINT)
#define EXCEPT_TAINT_MEM ((1 << 16) | EXCEPT_TAINT)
#define EXCEPT_UNTAINT_MEM ((1 << 17) | EXCEPT_TAINT)

#define ADD 1
#define REMOVE 2

#define TAINT_EVENT 1
#define UNTAINT_EVENT 2

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

struct taint_t {
	struct taint_color_t *colors;
	uint64_t nb_colors;
	uint64_t nb_registers;
	uint32_t max_register_size;
};

/* Colors */
struct taint_t* taint_init_colors(uint64_t nb_regs,
					 uint64_t nb_registers,
					 uint32_t max_register_size
					 );
struct taint_color_t taint_init_color(uint64_t nb_regs, uint32_t max_register_size);
void taint_check_color(uint64_t color_index, uint64_t nb_colors);
void taint_check_register(uint64_t register_index,
                          struct interval interval,
                          uint64_t nb_registers,
                          uint32_t max_register_size);

/* Registers */
_MIASM_EXPORT void taint_register_generic_access(struct taint_t *colors,
				   uint64_t color_index,
				   uint64_t register_index,
				   struct interval interval,
				   uint32_t access_type
				   );
_MIASM_EXPORT struct rb_root taint_get_register_color(struct taint_t *colors,
						    uint64_t color_index,
						    uint64_t register_index,
						    struct interval interval
						    );
struct rb_root taint_get_register(struct rb_root ** registers,
					      uint64_t register_index,
					      struct interval interval,
					      uint32_t max_register_size
					      );
void taint_color_init_registers(struct taint_color_t *color, uint64_t nb_registers);
void taint_remove_all_registers(struct taint_t *colors);
void taint_color_remove_all_registers(struct taint_t *colors,
				      uint64_t color_index
				      );

/* Memory */
_MIASM_EXPORT void taint_memory_generic_access(struct taint_t *colors,
                                               uint64_t color_index,
                                               struct interval interval,
                                               uint32_t access_type);
_MIASM_EXPORT struct rb_root taint_get_memory(struct taint_t *colors,
                                                uint64_t color_index,
                                                struct interval interval);
void taint_remove_all_memory(struct taint_t *colors);
void taint_color_remove_all_memory(struct taint_t *colors, uint64_t color_index);
void taint_color_init_memory(struct taint_color_t *color);

/* Callback information */
struct taint_callback_info_t *taint_init_callback_info(uint64_t nb_registers,
						       uint32_t max_register_size
						       );
_MIASM_EXPORT void taint_clean_all_callback_info(struct taint_t *colors);
void taint_clean_callback_info(struct taint_t *colors,
			       uint64_t color_index
			       );
_MIASM_EXPORT void taint_update_register_callback_info(struct taint_t *colors,
                                                       uint64_t color_index,
                                                       uint64_t register_index,
                                                       struct interval interval,
                                                       int event_type);
_MIASM_EXPORT void taint_update_memory_callback_info(struct taint_t *colors,
                                                     uint64_t color_index,
                                                     struct interval interval,
                                                     int event_type);
#endif
