
struct vm_cpu {
	uint32_t exception_flags;

	/* gpregs */
	uint32_t PC;
	uint32_t SP;
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
	uint32_t R13;
	uint32_t R14;
	uint32_t R15;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t of;
	uint32_t cf;

	uint32_t cpuoff;
	uint32_t gie;
	uint32_t osc;
	uint32_t scg0;
	uint32_t scg1;
	uint32_t res;

};

#define RETURN_PC return BlockDst;

_MIASM_EXPORT void dump_gpregs(struct vm_cpu* vmcpu);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);
