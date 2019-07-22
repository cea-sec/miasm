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

_MIASM_EXPORT void dump_gpregs(struct vm_cpu *);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);
