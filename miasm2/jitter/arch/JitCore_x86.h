#define uint128_t __uint128_t

typedef struct {
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
	uint64_t zf;
	uint64_t nf;
	uint64_t pf;
	uint64_t of;
	uint64_t cf;
	uint64_t af;
	uint64_t df;

	uint64_t tf;
	uint64_t i_f;
	uint64_t iopl_f;
	uint64_t nt;
	uint64_t rf;
	uint64_t vm;
	uint64_t ac;
	uint64_t vif;
	uint64_t vip;
	uint64_t i_d;

	uint64_t my_tick;

	uint64_t cond;

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


	uint64_t tsc1;
	uint64_t tsc2;


	uint64_t ES;
	uint64_t CS;
	uint64_t SS;
	uint64_t DS;
	uint64_t FS;
	uint64_t GS;

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
	uint128_t XMM0;
	uint128_t XMM1;
	uint128_t XMM2;
	uint128_t XMM3;
	uint128_t XMM4;
	uint128_t XMM5;
	uint128_t XMM6;
	uint128_t XMM7;
	uint128_t XMM8;
	uint128_t XMM9;
	uint128_t XMM10;
	uint128_t XMM11;
	uint128_t XMM12;
	uint128_t XMM13;
	uint128_t XMM14;
	uint128_t XMM15;

	uint32_t segm_base[0x10000];

}vm_cpu_t;

void dump_gpregs_32(vm_cpu_t* vmcpu);
void dump_gpregs_64(vm_cpu_t* vmcpu);
uint64_t segm2addr(JitCpu* jitcpu, uint64_t segm, uint64_t addr);

#define RETURN_PC return BlockDst;
