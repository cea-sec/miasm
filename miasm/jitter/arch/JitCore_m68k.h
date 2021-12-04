
struct vm_cpu {
	uint32_t exception_flags;
	uint32_t interrupt_num;

	/* gpregs */
	uint32_t A0;
	uint32_t A1;
	uint32_t A2;
	uint32_t A3;
	uint32_t A4;
	uint32_t A5;
	uint32_t A6;
	uint32_t SP;

	uint32_t D0;
	uint32_t D1;
	uint32_t D2;
	uint32_t D3;
	uint32_t D4;
	uint32_t D5;
	uint32_t D6;
	uint32_t D7;


	uint32_t PC;

	/* eflag */
	uint32_t zf;
	uint32_t nf;
	uint32_t vf;
	uint32_t cf;
	uint32_t xf;

	uint64_t float_st0;
	uint64_t float_st1;
	uint64_t float_st2;
	uint64_t float_st3;
	uint64_t float_st4;
	uint64_t float_st5;
	uint64_t float_st6;
	uint64_t float_st7;

	uint32_t bp_num;
};


_MIASM_EXPORT void dump_gpregs(struct vm_cpu* vmcpu);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);

#define RETURN_PC return BlockDst;
