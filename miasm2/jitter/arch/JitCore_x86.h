
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

	double float_st0;
	double float_st1;
	double float_st2;
	double float_st3;
	double float_st4;
	double float_st5;
	double float_st6;
	double float_st7;

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

	uint32_t segm_base[0x10000];

}vm_cpu_t;




void dump_gpregs_32(vm_cpu_t* vmcpu);
void dump_gpregs_64(vm_cpu_t* vmcpu);
uint64_t segm2addr(JitCpu* jitcpu, uint64_t segm, uint64_t addr);


uint64_t udiv64(vm_cpu_t* vmcpu, uint64_t a, uint64_t b);
uint64_t umod64(vm_cpu_t* vmcpu, uint64_t a, uint64_t b);
int64_t idiv64(vm_cpu_t* vmcpu, int64_t a, int64_t b);
int64_t imod64(vm_cpu_t* vmcpu, int64_t a, int64_t b);

uint32_t udiv32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
uint32_t umod32(vm_cpu_t* vmcpu, uint32_t a, uint32_t b);
int32_t idiv32(vm_cpu_t* vmcpu, int32_t a, int32_t b);
int32_t imod32(vm_cpu_t* vmcpu, int32_t a, int32_t b);

uint16_t udiv16(vm_cpu_t* vmcpu, uint16_t a, uint16_t b);
uint16_t umod16(vm_cpu_t* vmcpu, uint16_t a, uint16_t b);
int16_t idiv16(vm_cpu_t* vmcpu, int16_t a, int16_t b);
int16_t imod16(vm_cpu_t* vmcpu, int16_t a, int16_t b);

#define RETURN_PC return BlockDst;
