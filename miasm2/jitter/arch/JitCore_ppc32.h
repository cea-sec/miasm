/*
 * _size can't be used yet because all register accesses are homogeneously
 * 32-bit
 */
struct vm_cpu {
#define JITCORE_PPC_REG_EXPAND(_name, _size)				\
    uint32_t _name;
#include "JitCore_ppc32_regs.h"
#undef JITCORE_PPC_REG_EXPAND

    uint64_t exception_flags;
    uint32_t spr_access;
    uint32_t reserve;
    uint32_t reserve_address;
};

int32_t idiv32(struct vm_cpu *, int32_t, int32_t);
uint32_t udiv32(struct vm_cpu *, uint32_t, uint32_t);
int32_t imod32(struct vm_cpu *, int32_t, int32_t);
uint32_t umod32(struct vm_cpu *, uint32_t, uint32_t);

void dump_gpregs(struct vm_cpu *);

typedef struct vm_cpu vm_cpu_t;
