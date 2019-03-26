// Inspired from JitCore_msp430.h

struct vm_cpu {
	/* miasm flags */
	uint32_t exception_flags;

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
	uint32_t TP;
	uint32_t GP;
	uint32_t SP;

	/* csregs */
	uint32_t PC;
	uint32_t LP;
	uint32_t SAR;
	uint32_t S3;
	uint32_t RPB;
	uint32_t RPE;
	uint32_t RPC;
	uint32_t HI;
	uint32_t LO;
	uint32_t S9;
	uint32_t S10;
	uint32_t S11;
	uint32_t MB0;
	uint32_t ME0;
	uint32_t MB1;
	uint32_t ME1;
	uint32_t PSW;
	uint32_t ID;
	uint32_t TMP;
	uint32_t EPC;
	uint32_t EXC;
	uint32_t CFG;
	uint32_t S22;
	uint32_t NPC;
	uint32_t DBG;
	uint32_t DEPC;
	uint32_t OPT;
	uint32_t RCFG;
	uint32_t CCFG;
	uint32_t S29;
	uint32_t S30;
	uint32_t S31;
	uint32_t S32;

	/* miasm specific regs */
	uint32_t PC_end;
	uint32_t RPE_instr_count;
	uint32_t RPC_current;


	uint32_t take_jmp;
	uint32_t last_addr;
	uint32_t is_repeat_end;
	uint32_t in_erepeat;

	/* flags */

};

_MIASM_EXPORT void dump_gpregs(struct vm_cpu* vmcpu);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);

#define RETURN_PC return BlockDst;
