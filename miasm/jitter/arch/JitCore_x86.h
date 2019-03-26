#include "../bn.h"

#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

struct vm_cpu {
	uint32_t exception_flags;
	uint32_t interrupt_num;


	/* gpregs */
	uint64_t RAX;
	uint64_t RBX;
	uint64_t RCX;
	uint64_t RDX;
	uint64_t RSI;
	uint64_t RDI;
	uint64_t RSP;
	uint64_t RBP;
	uint64_t R8;
	uint64_t R9;
	uint64_t R10;
	uint64_t R11;
	uint64_t R12;
	uint64_t R13;
	uint64_t R14;
	uint64_t R15;

	uint64_t RIP;

	/* eflag */
	uint8_t zf;
	uint8_t nf;
	uint8_t pf;
	uint8_t of;
	uint8_t cf;
	uint8_t af;
	uint8_t df;

	uint8_t tf;
	uint8_t i_f;
	uint8_t iopl_f;
	uint8_t nt;
	uint8_t rf;
	uint8_t vm;
	uint8_t ac;
	uint8_t vif;
	uint8_t vip;
	uint8_t i_d;

	bn_t my_tick;

	bn_t cond;

	uint64_t float_st0;
	uint64_t float_st1;
	uint64_t float_st2;
	uint64_t float_st3;
	uint64_t float_st4;
	uint64_t float_st5;
	uint64_t float_st6;
	uint64_t float_st7;

	unsigned int float_c0;
	unsigned int float_c1;
	unsigned int float_c2;
	unsigned int float_c3;


	unsigned int float_stack_ptr;

	unsigned int reg_float_control;

	unsigned int reg_float_eip;
	unsigned int reg_float_cs;
	unsigned int reg_float_address;
	unsigned int reg_float_ds;


	uint64_t tsc;


	uint16_t ES;
	uint16_t CS;
	uint16_t SS;
	uint16_t DS;
	uint16_t FS;
	uint16_t GS;

	unsigned int cr0;
	unsigned int cr3;

	uint64_t MM0;
	uint64_t MM1;
	uint64_t MM2;
	uint64_t MM3;
	uint64_t MM4;
	uint64_t MM5;
	uint64_t MM6;
	uint64_t MM7;

	/* SSE */
	bn_t XMM0;
	bn_t XMM1;
	bn_t XMM2;
	bn_t XMM3;
	bn_t XMM4;
	bn_t XMM5;
	bn_t XMM6;
	bn_t XMM7;
	bn_t XMM8;
	bn_t XMM9;
	bn_t XMM10;
	bn_t XMM11;
	bn_t XMM12;
	bn_t XMM13;
	bn_t XMM14;
	bn_t XMM15;

	uint64_t segm_base[0x10000];

};

_MIASM_EXPORT void dump_gpregs_32(struct vm_cpu* vmcpu);
_MIASM_EXPORT void dump_gpregs_64(struct vm_cpu* vmcpu);
_MIASM_EXPORT uint64_t segm2addr(JitCpu* jitcpu, uint64_t segm, uint64_t addr);

_MIASM_EXPORT void MEM_WRITE_08(JitCpu* jitcpu, uint64_t addr, uint8_t src);
_MIASM_EXPORT void MEM_WRITE_16(JitCpu* jitcpu, uint64_t addr, uint16_t src);
_MIASM_EXPORT void MEM_WRITE_32(JitCpu* jitcpu, uint64_t addr, uint32_t src);
_MIASM_EXPORT void MEM_WRITE_64(JitCpu* jitcpu, uint64_t addr, uint64_t src);

#define RETURN_PC return BlockDst;
