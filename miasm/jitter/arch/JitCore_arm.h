
struct vm_cpu {
	uint32_t exception_flags;
	uint32_t interrupt_num;

	/* gpregs */
	uint32_t R0;
	uint32_t R1;
	uint32_t R2;
	uint32_t R3;
	uint32_t R4;
	uint32_t R5;
	uint32_t R6;
	uint32_t R7;
	uint32_t R8;
	uint32_t R9;
	uint32_t R10;
	uint32_t R11;
	uint32_t R12;
	uint32_t SP;
	uint32_t LR;
	uint32_t PC;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;

	/* ge */
	uint32_t ge0;
	uint32_t ge1;
	uint32_t ge2;
	uint32_t ge3;

	uint32_t bp_num;
};


_MIASM_EXPORT void dump_gpregs(struct vm_cpu* vmcpu);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);

#define RETURN_PC return BlockDst;
